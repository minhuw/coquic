package client

import (
	"fmt"
	"time"

	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/config"
	perfio "github.com/minhuw/coquic/bench/coquic-go-perf/internal/io"
	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/metrics"
	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/protocol"
	coquic "github.com/minhuw/coquic/bindings/go/coquic"
)

const (
	idleTimeout  = time.Second
	drainTimeout = 2 * time.Second
)

type benchmarkPhase int

const (
	phaseWarmup benchmarkPhase = iota
	phaseMeasure
	phaseDrain
)

type outstandingRequest struct {
	startedAt               coquic.TimeUs
	countsTowardMeasurement bool
}

type connectionState struct {
	sessionReady          bool
	controlComplete       bool
	closeRequested        bool
	controlBytes          []byte
	outstandingRequests   map[coquic.StreamID]outstandingRequest
	persistentRequests    []outstandingRequest
	activeBulkStreams     map[coquic.StreamID]bool
	nextStreamID          coquic.StreamID
	persistentStreamID    *coquic.StreamID
	persistentFinSent     bool
	persistentPendingRead uint64
	requestLimit          *uint64
	requestsStarted       uint64
	serverCompleteCounted bool
}

func newConnectionState(requestLimit *uint64) *connectionState {
	return &connectionState{
		outstandingRequests: make(map[coquic.StreamID]outstandingRequest),
		activeBulkStreams:   make(map[coquic.StreamID]bool),
		nextStreamID:        coquic.StreamID(protocol.FirstDataStreamID),
		requestLimit:        requestLimit,
	}
}

type commandKind int

const (
	commandOpenConnection commandKind = iota
	commandSendStream
	commandClose
)

type clientCommand struct {
	kind       commandKind
	connection coquic.ConnectionHandle
	streamID   coquic.StreamID
	bytes      []byte
	fin        bool
	reason     []byte
}

func Run(configValue config.PerfConfig) (metrics.RunSummary, error) {
	endpointConfig := config.ClientEndpointConfig(configValue)
	endpoint, err := coquic.NewEndpoint(endpointConfig)
	if err != nil {
		return metrics.RunSummary{}, err
	}
	defer endpoint.Destroy()

	ioRuntime, primaryRoute, primaryIdentity, err := perfio.NewClient(
		configValue.Host,
		configValue.Port,
		configValue.MaxOutboundDatagramSize,
	)
	if err != nil {
		return metrics.RunSummary{}, err
	}
	defer ioRuntime.Close()

	client := &Client{
		config:             configValue,
		endpoint:           endpoint,
		io:                 ioRuntime,
		primaryRoute:       primaryRoute,
		primaryIdentity:    primaryIdentity,
		connections:        make(map[coquic.ConnectionHandle]*connectionState),
		closingConnections: make(map[coquic.ConnectionHandle]bool),
		phase:              phaseWarmup,
		summary:            metrics.NewRunSummary(configValue),
	}
	return client.run()
}

type Client struct {
	config              config.PerfConfig
	endpoint            *coquic.Endpoint
	io                  *perfio.UdpRuntime
	primaryRoute        coquic.RouteHandle
	primaryIdentity     []byte
	connections         map[coquic.ConnectionHandle]*connectionState
	closingConnections  map[coquic.ConnectionHandle]bool
	requestsStarted     uint64
	crrRequestsOpened   uint64
	nextConnectionIndex uint64
	phase               benchmarkPhase
	runStartedAt        coquic.TimeUs
	benchmarkStartedAt  *coquic.TimeUs
	measureStartedAt    coquic.TimeUs
	measureDeadline     coquic.TimeUs
	drainDeadline       *coquic.TimeUs
	summary             metrics.RunSummary
}

func (c *Client) run() (metrics.RunSummary, error) {
	start := c.io.NowUs()
	c.runStartedAt = start
	c.measureStartedAt = start
	c.phase = phaseWarmup
	if !c.timedMode() {
		c.benchmarkStartedAt = timePtr(start)
	}

	for index := uint64(0); index < c.initialConnectionTarget(); index++ {
		result, err := c.executeCommand(clientCommand{kind: commandOpenConnection}, start)
		if err != nil {
			return c.summary, err
		}
		if err := c.handleResult(result, start); err != nil {
			return c.summary, err
		}
	}

	for {
		now := c.io.NowUs()
		if err := c.advanceBenchmarkPhase(now); err != nil {
			return c.summary, err
		}

		if c.runComplete() {
			if err := c.io.FlushSends(); err != nil {
				return c.summary, err
			}
			if c.timedBulkMode() &&
				c.config.Direction == config.DirectionDownload &&
				c.config.ResponseBytes > 0 &&
				c.summary.BytesReceived == 0 {
				return c.summary, fmt.Errorf("timed bulk download measured zero bytes")
			}
			c.summary.Status = "ok"
			c.summary.ElapsedMs = metrics.DurationMillis(c.resultElapsed(now))
			if c.timedRRMode() || c.timedPersistentRRMode() || c.timedCRRMode() {
				c.summary.ServerCounters = metrics.ServerCounters{
					BytesSent:         c.summary.BytesReceived,
					BytesReceived:     c.summary.BytesSent,
					RequestsCompleted: c.summary.RequestsCompleted,
				}
			}
			metrics.FinalizeSummary(&c.summary)
			return c.summary, nil
		}

		if err := c.handleDueTimer(); err != nil {
			return c.summary, err
		}
		if err := c.maybeOpenCRRConnections(); err != nil {
			return c.summary, err
		}
		if err := c.io.FlushSends(); err != nil {
			return c.summary, err
		}

		coreWakeup, hasCoreWakeup := c.endpoint.NextWakeup()
		nextWakeup, hasNextWakeup := c.nextWaitWakeup(coreWakeup, hasCoreWakeup)
		event, err := c.io.Wait(nextWakeup, hasNextWakeup, idleTimeout)
		if err != nil {
			return c.summary, err
		}
		switch event.Kind {
		case perfio.WaitDatagram:
			now := c.io.NowUs()
			if err := c.advanceBenchmarkPhase(now); err != nil {
				return c.summary, err
			}
			result, err := c.endpoint.ReceiveDatagram(c.io.InboundDatagram(event.Datagram), now)
			if err != nil {
				return c.summary, err
			}
			if err := c.handleResult(result, now); err != nil {
				return c.summary, err
			}
		case perfio.WaitTimer:
			now := c.io.NowUs()
			if err := c.advanceBenchmarkPhase(now); err != nil {
				return c.summary, err
			}
			if err := c.handleDueTimer(); err != nil {
				return c.summary, err
			}
		case perfio.WaitIdle:
			return c.summary, fmt.Errorf("client timed out waiting for progress")
		}
	}
}

func (c *Client) handleDueTimer() error {
	for {
		wakeup, ok := c.endpoint.NextWakeup()
		if !ok {
			return nil
		}
		now := c.io.NowUs()
		if wakeup > now {
			return nil
		}
		result, err := c.endpoint.TimerExpired(now)
		if err != nil {
			return err
		}
		if err := c.handleResult(result, now); err != nil {
			return err
		}
	}
}

func (c *Client) handleResult(result *coquic.QueryResult, now coquic.TimeUs) error {
	pending := []*coquic.QueryResult{result}
	for index := 0; index < len(pending); index++ {
		current := pending[index]
		commands, err := c.collectResultCommands(current, now)
		current.Destroy()
		if err != nil {
			return err
		}
		for _, command := range commands {
			next, err := c.executeCommand(command, now)
			if err != nil {
				return err
			}
			pending = append(pending, next)
		}
	}
	return c.io.FlushSends()
}

func (c *Client) collectResultCommands(result *coquic.QueryResult, now coquic.TimeUs) ([]clientCommand, error) {
	c.advanceBenchmarkPhaseSync(now)
	localError, err := result.LocalError()
	if err != nil {
		return nil, err
	}
	if localError != nil {
		c.summary.FailureReason = fmt.Sprintf("client local error: %+v", *localError)
		return nil, fmt.Errorf("%s", c.summary.FailureReason)
	}

	effects, err := c.io.CollectResultEffects(result)
	if err != nil {
		return nil, err
	}

	commands := make([]clientCommand, 0)
	for _, effect := range effects {
		switch effect.Kind {
		case coquic.EffectConnectionLifecycleEvent:
			switch effect.Lifecycle {
			case coquic.LifecycleCreated:
				connectionIndex := uint64(len(c.connections))
				if _, ok := c.connections[effect.Connection]; !ok {
					c.connections[effect.Connection] = newConnectionState(
						c.requestLimitForConnection(connectionIndex),
					)
				}
			case coquic.LifecycleClosed:
				if c.config.Mode == config.ModeCRR {
					delete(c.connections, effect.Connection)
				} else if state, ok := c.connections[effect.Connection]; ok {
					state.controlComplete = true
				}
			}
		case coquic.EffectStateEvent:
			if effect.StateChange == coquic.StateChangeFailed &&
				!c.closingConnections[effect.Connection] {
				return nil, fmt.Errorf("client core state failed connection=%d", effect.Connection)
			}
			if effect.StateChange == coquic.StateChangeHandshakeReady {
				if _, ok := c.connections[effect.Connection]; ok {
					commands = append(commands, clientCommand{
						kind:       commandSendStream,
						connection: effect.Connection,
						streamID:   coquic.StreamID(protocol.ControlStreamID),
						bytes: protocol.EncodeControlMessage(
							c.makeSessionStart(c.connections[effect.Connection].requestLimit),
						),
						fin: true,
					})
				}
			}
		case coquic.EffectReceiveStreamData:
			next, err := c.handleStreamData(effect.Connection, effect.StreamID, effect.Bytes, effect.Fin, now)
			if err != nil {
				return nil, err
			}
			commands = append(commands, next...)
		}
	}
	return commands, nil
}

func (c *Client) handleStreamData(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	data []byte,
	fin bool,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	if uint64(streamID) == protocol.ControlStreamID {
		return c.handleControlStreamData(connection, data, fin, now)
	}
	if c.timedBulkMode() {
		return c.handleBulkData(connection, streamID, data, fin, now)
	}
	if c.config.Mode == config.ModePersistentRR {
		return c.handlePersistentRRData(connection, streamID, data, now)
	}
	if c.config.Mode == config.ModeRR || c.config.Mode == config.ModeCRR {
		return c.handleRequestResponseData(connection, streamID, data, fin, now)
	}
	c.summary.BytesReceived += uint64(len(data))
	return nil, nil
}

func (c *Client) handleControlStreamData(
	connection coquic.ConnectionHandle,
	data []byte,
	fin bool,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	state, ok := c.connections[connection]
	if !ok {
		return nil, fmt.Errorf("control data for unknown connection")
	}
	state.controlBytes = append(state.controlBytes, data...)

	messages := make([]protocol.ControlMessage, 0)
	for {
		message, ok := protocol.TakeControlMessage(&state.controlBytes)
		if !ok {
			break
		}
		messages = append(messages, message)
	}

	commands := make([]clientCommand, 0)
	for _, message := range messages {
		next, err := c.handleControlMessage(connection, state, message, now)
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
	}
	if fin && len(state.controlBytes) != 0 {
		return nil, fmt.Errorf("incomplete control frame at FIN")
	}
	return commands, nil
}

func (c *Client) handleControlMessage(
	connection coquic.ConnectionHandle,
	state *connectionState,
	message protocol.ControlMessage,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	switch value := message.(type) {
	case protocol.SessionReady:
		_ = value
		state.sessionReady = true
		c.maybeStartTimedBenchmark(now)
		return c.startWorkForConnection(connection, now)
	case protocol.SessionError:
		state.controlComplete = true
		return nil, fmt.Errorf("%s", value.Reason)
	case protocol.SessionComplete:
		if !state.serverCompleteCounted {
			c.summary.ServerCounters.BytesSent += value.BytesSent
			c.summary.ServerCounters.BytesReceived += value.BytesReceived
			c.summary.ServerCounters.RequestsCompleted += value.RequestsCompleted
			state.serverCompleteCounted = true
		}
		if c.config.Mode == config.ModeBulk {
			c.summary.RequestsCompleted = c.summary.ServerCounters.RequestsCompleted
		}
		state.controlComplete = true
		return nil, nil
	default:
		return nil, fmt.Errorf("client received unexpected session_start")
	}
}

func (c *Client) handleBulkData(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	data []byte,
	fin bool,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	state := c.connections[connection]
	counts := false
	if state != nil {
		counts = state.activeBulkStreams[streamID]
	}
	withinWindow := now >= c.measureStartedAt && now < c.measureDeadline
	if c.config.Direction == config.DirectionDownload && counts && withinWindow {
		c.summary.BytesReceived += uint64(len(data))
	}
	if !fin {
		return nil, nil
	}
	if state != nil {
		delete(state.activeBulkStreams, streamID)
	}
	commands, err := c.maybeStartBulkStreams(connection, now)
	if err != nil {
		return nil, err
	}
	state = c.connections[connection]
	if c.phase == phaseDrain && state != nil && len(state.activeBulkStreams) == 0 {
		next, err := c.maybeCloseBulkConnection(connection)
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
	}
	return commands, nil
}

func (c *Client) handleRequestResponseData(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	data []byte,
	fin bool,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	state := c.connections[connection]
	if state == nil {
		return nil, nil
	}
	request, ok := state.outstandingRequests[streamID]
	if !ok {
		return nil, nil
	}
	if request.countsTowardMeasurement {
		c.summary.BytesReceived += uint64(len(data))
	}
	if !fin {
		return nil, nil
	}
	return c.finishRequestResponseStream(connection, streamID, state, request, now)
}

func (c *Client) handlePersistentRRData(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	data []byte,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	state := c.connections[connection]
	if state == nil || state.persistentStreamID == nil || *state.persistentStreamID != streamID {
		return nil, nil
	}
	state.persistentPendingRead += uint64(len(data))
	responseBytes := c.config.ResponseBytes
	for state.persistentPendingRead >= responseBytes && len(state.persistentRequests) > 0 {
		request := state.persistentRequests[0]
		copy(state.persistentRequests, state.persistentRequests[1:])
		state.persistentRequests = state.persistentRequests[:len(state.persistentRequests)-1]
		state.persistentPendingRead -= responseBytes
		if request.countsTowardMeasurement {
			c.summary.BytesReceived += responseBytes
			elapsed := time.Duration(uint64(now-request.startedAt)) * time.Microsecond
			c.summary.LatencySamples = append(c.summary.LatencySamples, elapsed)
			c.summary.RequestsCompleted++
		}
	}
	if c.phase == phaseDrain {
		if len(state.persistentRequests) == 0 {
			return c.maybeClosePersistentRRConnection(connection)
		}
		return nil, nil
	}
	return c.maybeIssuePersistentRRRequests(connection, now)
}

func (c *Client) finishRequestResponseStream(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	state *connectionState,
	request outstandingRequest,
	now coquic.TimeUs,
) ([]clientCommand, error) {
	if request.countsTowardMeasurement {
		elapsed := time.Duration(uint64(now-request.startedAt)) * time.Microsecond
		c.summary.LatencySamples = append(c.summary.LatencySamples, elapsed)
		c.summary.RequestsCompleted++
	}
	delete(state.outstandingRequests, streamID)
	if c.config.Mode == config.ModeRR {
		if c.phase == phaseDrain && len(state.outstandingRequests) == 0 {
			return c.maybeCloseRRConnection(connection)
		}
		return c.maybeIssueRRRequests(connection, now)
	}
	if !state.closeRequested {
		return c.closeConnection(connection, []byte("done"))
	}
	return nil, nil
}

func (c *Client) executeCommand(command clientCommand, now coquic.TimeUs) (*coquic.QueryResult, error) {
	switch command.kind {
	case commandOpenConnection:
		clientConfig := c.makeClientConfig(c.nextConnectionIndex)
		c.nextConnectionIndex++
		clientConfig.InitialRouteHandle = c.primaryRoute
		clientConfig.AddressValidationIdentity = append([]byte(nil), c.primaryIdentity...)
		_, result, err := c.endpoint.Connect(clientConfig, now)
		return result, err
	case commandSendStream:
		return c.endpoint.SendStream(command.connection, command.streamID, command.bytes, command.fin, now)
	case commandClose:
		c.closingConnections[command.connection] = true
		return c.endpoint.CloseConnection(command.connection, 0, command.reason, now)
	default:
		return nil, fmt.Errorf("unknown client command")
	}
}

func (c *Client) startWorkForConnection(connection coquic.ConnectionHandle, now coquic.TimeUs) ([]clientCommand, error) {
	commands := make([]clientCommand, 0)
	next, err := c.maybeStartBulkStreams(connection, now)
	if err != nil {
		return nil, err
	}
	commands = append(commands, next...)
	next, err = c.maybeIssueRRRequests(connection, now)
	if err != nil {
		return nil, err
	}
	commands = append(commands, next...)
	next, err = c.maybeIssuePersistentRRRequests(connection, now)
	if err != nil {
		return nil, err
	}
	commands = append(commands, next...)
	next, err = c.maybeIssueCRRRequest(connection, now)
	if err != nil {
		return nil, err
	}
	commands = append(commands, next...)
	return commands, nil
}

func (c *Client) maybeStartBulkStreams(connection coquic.ConnectionHandle, _ coquic.TimeUs) ([]clientCommand, error) {
	if c.config.Mode != config.ModeBulk {
		return nil, nil
	}
	state := c.connections[connection]
	if state == nil || !state.sessionReady || state.controlComplete {
		return nil, nil
	}

	if c.timedBulkMode() {
		if c.phase == phaseDrain {
			return nil, nil
		}
		commands := make([]clientCommand, 0)
		for uint64(len(state.activeBulkStreams)) < c.config.Streams && c.benchmarkAcceptsNewWork() {
			next, err := c.openBulkStream(connection, c.phase == phaseMeasure)
			if err != nil {
				return nil, err
			}
			commands = append(commands, next...)
		}
		return commands, nil
	}

	if uint64(state.nextStreamID) != protocol.FirstDataStreamID {
		return nil, nil
	}

	totalBytes := uint64(0)
	if c.config.TotalBytes != nil {
		totalBytes = *c.config.TotalBytes
	}
	perStream := totalBytes / c.config.Streams
	remainder := totalBytes % c.config.Streams
	commands := make([]clientCommand, 0, c.config.Streams)
	for index := uint64(0); index < c.config.Streams; index++ {
		streamID, err := c.nextStreamID(connection)
		if err != nil {
			return nil, err
		}
		targetBytes := perStream
		if index < remainder {
			targetBytes++
		}
		payload := []byte(nil)
		if c.config.Direction == config.DirectionUpload {
			c.summary.BytesSent += targetBytes
			payload = makePayload(targetBytes)
		}
		commands = append(commands, clientCommand{
			kind:       commandSendStream,
			connection: connection,
			streamID:   streamID,
			bytes:      payload,
			fin:        true,
		})
	}
	return commands, nil
}

func (c *Client) openBulkStream(connection coquic.ConnectionHandle, countsTowardMeasurement bool) ([]clientCommand, error) {
	streamID, err := c.nextStreamID(connection)
	if err != nil {
		return nil, err
	}
	state := c.connections[connection]
	if state == nil {
		return nil, fmt.Errorf("bulk stream for unknown connection")
	}
	state.activeBulkStreams[streamID] = countsTowardMeasurement
	payload := []byte(nil)
	if c.config.Direction == config.DirectionUpload {
		payload = makePayload(maxU64(c.config.RequestBytes, c.config.ResponseBytes))
		if countsTowardMeasurement {
			c.summary.BytesSent += uint64(len(payload))
		}
	}
	return []clientCommand{{
		kind:       commandSendStream,
		connection: connection,
		streamID:   streamID,
		bytes:      payload,
		fin:        true,
	}}, nil
}

func (c *Client) maybeIssueRRRequests(connection coquic.ConnectionHandle, now coquic.TimeUs) ([]clientCommand, error) {
	if c.config.Mode != config.ModeRR || !c.benchmarkAcceptsNewWork() {
		return nil, nil
	}
	state := c.connections[connection]
	if state == nil || !state.sessionReady || state.controlComplete {
		return nil, nil
	}

	commands := make([]clientCommand, 0)
	for uint64(len(state.outstandingRequests)) < c.config.RequestsInFlight &&
		(c.config.Requests == nil || c.requestsStarted < *c.config.Requests) &&
		(state.requestLimit == nil || state.requestsStarted < *state.requestLimit) {
		next, err := c.issueRequest(connection, now)
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
		c.requestsStarted++
	}
	return commands, nil
}

func (c *Client) maybeIssuePersistentRRRequests(connection coquic.ConnectionHandle, now coquic.TimeUs) ([]clientCommand, error) {
	if c.config.Mode != config.ModePersistentRR || !c.benchmarkAcceptsNewWork() {
		return nil, nil
	}
	state := c.connections[connection]
	if state == nil || !state.sessionReady || state.controlComplete || state.closeRequested || state.persistentFinSent {
		return nil, nil
	}
	if state.persistentStreamID == nil {
		streamID, err := c.nextStreamID(connection)
		if err != nil {
			return nil, err
		}
		state.persistentStreamID = &streamID
	}

	commands := make([]clientCommand, 0)
	for uint64(len(state.persistentRequests)) < c.config.RequestsInFlight &&
		(c.config.Requests == nil || c.requestsStarted < *c.config.Requests) &&
		(state.requestLimit == nil || state.requestsStarted < *state.requestLimit) {
		counts := c.config.Requests != nil || c.phase == phaseMeasure
		state.persistentRequests = append(state.persistentRequests, outstandingRequest{
			startedAt:               now,
			countsTowardMeasurement: counts,
		})
		state.requestsStarted++
		c.requestsStarted++
		if counts {
			c.summary.BytesSent += c.config.RequestBytes
		}
		commands = append(commands, clientCommand{
			kind:       commandSendStream,
			connection: connection,
			streamID:   *state.persistentStreamID,
			bytes:      makePayload(c.config.RequestBytes),
			fin:        false,
		})
	}

	if c.config.Requests != nil &&
		(state.requestLimit == nil || state.requestsStarted >= *state.requestLimit) {
		next, err := c.maybeFinishPersistentRRStream(connection)
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
	}
	return commands, nil
}

func (c *Client) maybeIssueCRRRequest(connection coquic.ConnectionHandle, now coquic.TimeUs) ([]clientCommand, error) {
	if c.config.Mode != config.ModeCRR {
		return nil, nil
	}
	state := c.connections[connection]
	canIssue := state != nil &&
		state.sessionReady &&
		!state.controlComplete &&
		!state.closeRequested &&
		len(state.outstandingRequests) == 0
	if !canIssue {
		return nil, nil
	}
	if !c.benchmarkAcceptsNewWork() {
		return c.maybeCloseCRRConnection(connection)
	}
	return c.issueRequest(connection, now)
}

func (c *Client) issueRequest(connection coquic.ConnectionHandle, now coquic.TimeUs) ([]clientCommand, error) {
	streamID, err := c.nextStreamID(connection)
	if err != nil {
		return nil, err
	}
	counts := c.config.Requests != nil || c.phase == phaseMeasure
	state := c.connections[connection]
	if state == nil {
		return nil, fmt.Errorf("request for unknown connection")
	}
	state.outstandingRequests[streamID] = outstandingRequest{
		startedAt:               now,
		countsTowardMeasurement: counts,
	}
	state.requestsStarted++
	if counts {
		c.summary.BytesSent += c.config.RequestBytes
	}
	return []clientCommand{{
		kind:       commandSendStream,
		connection: connection,
		streamID:   streamID,
		bytes:      makePayload(c.config.RequestBytes),
		fin:        true,
	}}, nil
}

func (c *Client) maybeOpenCRRConnections() error {
	if c.config.Mode != config.ModeCRR || !c.benchmarkAcceptsNewWork() {
		return nil
	}
	for uint64(len(c.connections)) < c.config.Connections &&
		(c.config.Requests == nil || c.crrRequestsOpened < *c.config.Requests) {
		now := c.io.NowUs()
		result, err := c.executeCommand(clientCommand{kind: commandOpenConnection}, now)
		if err != nil {
			return err
		}
		c.crrRequestsOpened++
		if err := c.handleResult(result, now); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) maybeCloseRRConnection(connection coquic.ConnectionHandle) ([]clientCommand, error) {
	force := c.timedRRMode() && c.phase == phaseDrain
	state := c.connections[connection]
	if state == nil || state.closeRequested || (!force && len(state.outstandingRequests) != 0) {
		return nil, nil
	}
	return c.closeConnection(connection, []byte("timed rr drain complete"))
}

func (c *Client) maybeFinishPersistentRRStream(connection coquic.ConnectionHandle) ([]clientCommand, error) {
	state := c.connections[connection]
	if state == nil {
		return nil, nil
	}
	if state.persistentStreamID == nil {
		if c.phase == phaseDrain && len(state.persistentRequests) == 0 {
			return c.maybeClosePersistentRRConnection(connection)
		}
		return nil, nil
	}
	if state.persistentFinSent {
		if c.phase == phaseDrain && len(state.persistentRequests) == 0 {
			return c.maybeClosePersistentRRConnection(connection)
		}
		return nil, nil
	}
	state.persistentFinSent = true
	commands := []clientCommand{{
		kind:       commandSendStream,
		connection: connection,
		streamID:   *state.persistentStreamID,
		bytes:      nil,
		fin:        true,
	}}
	if c.phase == phaseDrain && len(state.persistentRequests) == 0 {
		next, err := c.maybeClosePersistentRRConnection(connection)
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
	}
	return commands, nil
}

func (c *Client) maybeClosePersistentRRConnection(connection coquic.ConnectionHandle) ([]clientCommand, error) {
	force := c.timedPersistentRRMode() && c.phase == phaseDrain
	state := c.connections[connection]
	if state == nil || state.closeRequested || (!force && len(state.persistentRequests) != 0) {
		return nil, nil
	}
	if !state.persistentFinSent {
		return c.maybeFinishPersistentRRStream(connection)
	}
	return c.closeConnection(connection, []byte("persistent rr drain complete"))
}

func (c *Client) maybeCloseBulkConnection(connection coquic.ConnectionHandle) ([]clientCommand, error) {
	state := c.connections[connection]
	if state == nil || state.closeRequested || len(state.activeBulkStreams) != 0 {
		return nil, nil
	}
	return c.closeConnection(connection, []byte("timed bulk drain complete"))
}

func (c *Client) maybeCloseCRRConnection(connection coquic.ConnectionHandle) ([]clientCommand, error) {
	force := c.timedCRRMode() && c.phase == phaseDrain
	state := c.connections[connection]
	if state == nil || state.closeRequested || (!force && len(state.outstandingRequests) != 0) {
		return nil, nil
	}
	return c.closeConnection(connection, []byte("timed crr drain complete"))
}

func (c *Client) closeConnection(connection coquic.ConnectionHandle, reason []byte) ([]clientCommand, error) {
	if state := c.connections[connection]; state != nil {
		if state.closeRequested {
			return nil, nil
		}
		state.closeRequested = true
	}
	c.closingConnections[connection] = true
	return []clientCommand{{
		kind:       commandClose,
		connection: connection,
		reason:     reason,
	}}, nil
}

func (c *Client) advanceBenchmarkPhase(now coquic.TimeUs) error {
	c.advanceBenchmarkPhaseSync(now)
	if c.phase == phaseMeasure && now >= c.measureDeadline {
		if err := c.enterDrainPhase(now); err != nil {
			return err
		}
	}
	return c.forceCloseTimedDrain(now)
}

func (c *Client) advanceBenchmarkPhaseSync(now coquic.TimeUs) {
	if c.benchmarkStartedAt == nil || !c.timedMode() {
		return
	}
	if c.phase == phaseWarmup &&
		uint64(now-*c.benchmarkStartedAt) >= durationUs(c.config.Warmup) {
		c.enterMeasurePhase(now)
	}
}

func (c *Client) forceCloseTimedDrain(now coquic.TimeUs) error {
	commands, err := c.forceCloseTimedDrainCommands(now)
	if err != nil {
		return err
	}
	for _, command := range commands {
		result, err := c.executeCommand(command, now)
		if err != nil {
			return err
		}
		if err := c.handleResult(result, now); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) forceCloseTimedDrainCommands(now coquic.TimeUs) ([]clientCommand, error) {
	if !c.timedMode() || c.phase != phaseDrain {
		return nil, nil
	}
	if c.drainDeadline == nil || now < *c.drainDeadline {
		return nil, nil
	}

	commands := make([]clientCommand, 0, len(c.connections))
	handles := make([]coquic.ConnectionHandle, 0, len(c.connections))
	for handle := range c.connections {
		handles = append(handles, handle)
	}
	for _, handle := range handles {
		var next []clientCommand
		var err error
		switch c.config.Mode {
		case config.ModeBulk:
			if state := c.connections[handle]; state != nil {
				clear(state.activeBulkStreams)
			}
			next, err = c.maybeCloseBulkConnection(handle)
		case config.ModeRR:
			next, err = c.maybeCloseRRConnection(handle)
		case config.ModePersistentRR:
			next, err = c.maybeClosePersistentRRConnection(handle)
		case config.ModeCRR:
			next, err = c.maybeCloseCRRConnection(handle)
		}
		if err != nil {
			return nil, err
		}
		commands = append(commands, next...)
	}
	return commands, nil
}

func (c *Client) maybeStartTimedBenchmark(now coquic.TimeUs) {
	if !c.timedMode() || c.benchmarkStartedAt != nil {
		return
	}
	c.benchmarkStartedAt = timePtr(now)
	c.runStartedAt = now
	c.measureStartedAt = now
	c.phase = phaseWarmup
	if c.config.Warmup == 0 {
		c.enterMeasurePhase(now)
	}
}

func (c *Client) enterMeasurePhase(now coquic.TimeUs) {
	c.phase = phaseMeasure
	c.measureStartedAt = now
	c.measureDeadline = now + coquic.TimeUs(durationUs(c.config.Duration))
	metrics.ResetMeasurement(&c.summary)
	for _, state := range c.connections {
		for streamID, request := range state.outstandingRequests {
			request.countsTowardMeasurement = false
			state.outstandingRequests[streamID] = request
		}
		for index := range state.persistentRequests {
			state.persistentRequests[index].countsTowardMeasurement = false
		}
		for streamID := range state.activeBulkStreams {
			state.activeBulkStreams[streamID] = true
		}
	}
}

func (c *Client) enterDrainPhase(now coquic.TimeUs) error {
	if c.phase == phaseDrain {
		return nil
	}
	c.phase = phaseDrain
	c.summary.ElapsedMs = metrics.DurationMillis(c.resultElapsed(now))
	if c.timedMode() {
		drain := c.config.Duration
		if drain > drainTimeout {
			drain = drainTimeout
		}
		c.drainDeadline = timePtr(now + coquic.TimeUs(durationUs(drain)))
	}

	handles := make([]coquic.ConnectionHandle, 0, len(c.connections))
	for handle := range c.connections {
		handles = append(handles, handle)
	}
	for _, handle := range handles {
		var commands []clientCommand
		var err error
		switch {
		case c.config.Mode == config.ModeRR:
			commands, err = c.maybeCloseRRConnection(handle)
		case c.config.Mode == config.ModePersistentRR:
			commands, err = c.maybeFinishPersistentRRStream(handle)
		case c.config.Mode == config.ModeCRR:
			commands, err = c.maybeCloseCRRConnection(handle)
		case c.timedBulkMode():
			commands, err = c.maybeCloseBulkConnection(handle)
		}
		if err != nil {
			return err
		}
		for _, command := range commands {
			result, err := c.executeCommand(command, now)
			if err != nil {
				return err
			}
			if err := c.handleResult(result, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) timedRRMode() bool {
	return c.config.Mode == config.ModeRR && c.config.Requests == nil
}

func (c *Client) timedPersistentRRMode() bool {
	return c.config.Mode == config.ModePersistentRR && c.config.Requests == nil
}

func (c *Client) timedCRRMode() bool {
	return c.config.Mode == config.ModeCRR && c.config.Requests == nil
}

func (c *Client) timedBulkMode() bool {
	return c.config.Mode == config.ModeBulk && c.config.TotalBytes == nil
}

func (c *Client) timedMode() bool {
	return c.timedRRMode() || c.timedPersistentRRMode() || c.timedCRRMode() || c.timedBulkMode()
}

func (c *Client) benchmarkAcceptsNewWork() bool {
	return c.phase != phaseDrain
}

func (c *Client) benchmarkNextWakeup() (coquic.TimeUs, bool) {
	if !c.timedMode() || c.benchmarkStartedAt == nil {
		return 0, false
	}
	switch c.phase {
	case phaseWarmup:
		return *c.benchmarkStartedAt + coquic.TimeUs(durationUs(c.config.Warmup)), true
	case phaseMeasure:
		return c.measureDeadline, true
	case phaseDrain:
		if c.drainDeadline != nil {
			return *c.drainDeadline, true
		}
	}
	return 0, false
}

func (c *Client) nextWaitWakeup(core coquic.TimeUs, hasCore bool) (coquic.TimeUs, bool) {
	benchmark, hasBenchmark := c.benchmarkNextWakeup()
	switch {
	case hasCore && hasBenchmark:
		if core < benchmark {
			return core, true
		}
		return benchmark, true
	case hasCore:
		return core, true
	case hasBenchmark:
		return benchmark, true
	default:
		return 0, false
	}
}

func (c *Client) resultElapsed(now coquic.TimeUs) time.Duration {
	if c.timedMode() {
		if c.phase == phaseWarmup {
			return 0
		}
		measurementNow := now
		if c.phase == phaseDrain {
			measurementNow = c.measureDeadline
		}
		return time.Duration(uint64(measurementNow-c.measureStartedAt)) * time.Microsecond
	}
	return time.Duration(uint64(now-c.runStartedAt)) * time.Microsecond
}

func (c *Client) runComplete() bool {
	if c.config.Mode != config.ModeCRR && len(c.connections) == 0 {
		return false
	}

	switch c.config.Mode {
	case config.ModeBulk:
		if c.timedBulkMode() {
			if c.phase != phaseDrain {
				return false
			}
			for _, state := range c.connections {
				if !state.closeRequested || len(state.activeBulkStreams) != 0 {
					return false
				}
			}
			return true
		}
		for _, state := range c.connections {
			if !state.controlComplete {
				return false
			}
		}
		if c.config.TotalBytes != nil {
			if c.config.Direction == config.DirectionDownload {
				return c.summary.BytesReceived >= *c.config.TotalBytes
			}
			return c.summary.BytesSent >= *c.config.TotalBytes
		}
		return true
	case config.ModeRR:
		if c.timedRRMode() {
			if c.phase != phaseDrain {
				return false
			}
			for _, state := range c.connections {
				if !state.closeRequested {
					return false
				}
			}
			return true
		}
		if c.config.Requests == nil || c.summary.RequestsCompleted < *c.config.Requests {
			return false
		}
		for _, state := range c.connections {
			if !state.controlComplete || len(state.outstandingRequests) != 0 {
				return false
			}
		}
		return true
	case config.ModePersistentRR:
		if c.timedPersistentRRMode() {
			if c.phase != phaseDrain {
				return false
			}
			for _, state := range c.connections {
				if !state.closeRequested {
					return false
				}
			}
			return true
		}
		if c.config.Requests == nil || c.summary.RequestsCompleted < *c.config.Requests {
			return false
		}
		for _, state := range c.connections {
			if !state.controlComplete || len(state.persistentRequests) != 0 {
				return false
			}
		}
		return true
	case config.ModeCRR:
		if c.timedCRRMode() {
			if c.phase != phaseDrain {
				return false
			}
			for _, state := range c.connections {
				if !state.closeRequested {
					return false
				}
			}
			return true
		}
		return c.config.Requests != nil &&
			c.summary.RequestsCompleted >= *c.config.Requests &&
			len(c.connections) == 0
	default:
		return false
	}
}

func (c *Client) initialConnectionTarget() uint64 {
	if c.config.Mode == config.ModeCRR {
		return 0
	}
	return c.rrConnectionTarget()
}

func (c *Client) requestLimitForConnection(connectionIndex uint64) *uint64 {
	if (c.config.Mode != config.ModeRR && c.config.Mode != config.ModePersistentRR) || c.config.Requests == nil {
		return nil
	}
	connections := c.rrConnectionTarget()
	base := *c.config.Requests / connections
	remainder := *c.config.Requests % connections
	if connectionIndex < remainder {
		base++
	}
	limit := base
	return &limit
}

func (c *Client) rrConnectionTarget() uint64 {
	if (c.config.Mode == config.ModeRR || c.config.Mode == config.ModePersistentRR) &&
		c.config.Requests != nil &&
		*c.config.Requests < c.config.Connections {
		return *c.config.Requests
	}
	return c.config.Connections
}

func (c *Client) makeClientConfig(index uint64) coquic.ClientConfig {
	sequence := index + 1
	clientConfig := coquic.NewClientConfig(
		makeConnectionID(0xc1, sequence),
		makeConnectionID(0x83, 0x40+sequence),
	)
	clientConfig.ServerName = []byte(c.config.ServerName)
	return clientConfig
}

func (c *Client) makeSessionStart(requestLimit *uint64) protocol.SessionStart {
	requests := cloneOptional(c.config.Requests)
	if requestLimit != nil {
		requests = cloneOptional(requestLimit)
	}
	return protocol.SessionStart{
		ProtocolVersion:  protocol.ProtocolVersion,
		Mode:             c.config.Mode,
		Direction:        c.config.Direction,
		RequestBytes:     c.config.RequestBytes,
		ResponseBytes:    c.config.ResponseBytes,
		TotalBytes:       cloneOptional(c.config.TotalBytes),
		Requests:         requests,
		Warmup:           c.config.Warmup,
		Duration:         c.config.Duration,
		Streams:          c.config.Streams,
		Connections:      c.config.Connections,
		RequestsInFlight: c.config.RequestsInFlight,
	}
}

func (c *Client) nextStreamID(connection coquic.ConnectionHandle) (coquic.StreamID, error) {
	state := c.connections[connection]
	if state == nil {
		return 0, fmt.Errorf("unknown connection")
	}
	streamID := state.nextStreamID
	state.nextStreamID = coquic.StreamID(protocol.NextClientStreamID(uint64(streamID)))
	return streamID, nil
}

func makePayload(size uint64) []byte {
	return makePayloadByte(size, 0x5a)
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func makePayloadByte(size uint64, value byte) []byte {
	payload := make([]byte, int(size))
	for index := range payload {
		payload[index] = value
	}
	return payload
}

func makeConnectionID(prefix byte, sequence uint64) []byte {
	connectionID := make([]byte, 8)
	connectionID[0] = prefix
	for index := 1; index < len(connectionID); index++ {
		shift := uint((len(connectionID) - 1 - index) * 8)
		connectionID[index] = byte((sequence >> shift) & 0xff)
	}
	return connectionID
}

func durationUs(duration time.Duration) uint64 {
	return uint64(duration / time.Microsecond)
}

func timePtr(value coquic.TimeUs) *coquic.TimeUs {
	return &value
}

func cloneOptional(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
