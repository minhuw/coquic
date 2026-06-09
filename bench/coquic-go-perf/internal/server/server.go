package server

import (
	"fmt"
	"os"
	"time"

	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/config"
	perfio "github.com/minhuw/coquic/bench/coquic-go-perf/internal/io"
	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/metrics"
	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/protocol"
	coquic "github.com/minhuw/coquic/bindings/go/coquic"
)

const idleTimeout = time.Second

type session struct {
	controlBytes      []byte
	start             *protocol.SessionStart
	completeSent      bool
	bytesSent         uint64
	bytesReceived     uint64
	requestsCompleted uint64
}

type commandKind int

const (
	commandSendResponse commandKind = iota
	commandSendControl
)

type serverCommand struct {
	kind       commandKind
	connection coquic.ConnectionHandle
	streamID   coquic.StreamID
	bytes      uint64
	message    protocol.ControlMessage
}

func Run(configValue config.PerfConfig) (metrics.RunSummary, error) {
	endpointConfig, err := config.ServerEndpointConfig(configValue)
	if err != nil {
		return metrics.RunSummary{}, err
	}
	endpoint, err := coquic.NewEndpoint(endpointConfig)
	if err != nil {
		return metrics.RunSummary{}, err
	}
	defer endpoint.Destroy()

	ioRuntime, err := perfio.NewServer(configValue.Host, configValue.Port)
	if err != nil {
		return metrics.RunSummary{}, err
	}
	defer ioRuntime.Close()

	server := &Server{
		endpoint:             endpoint,
		io:                   ioRuntime,
		sessions:             make(map[coquic.ConnectionHandle]*session),
		completedCRRSessions: make(map[coquic.ConnectionHandle]bool),
	}
	if err := server.run(); err != nil {
		return metrics.RunSummary{}, err
	}
	return metrics.NewRunSummary(configValue), nil
}

type Server struct {
	endpoint             *coquic.Endpoint
	io                   *perfio.UdpRuntime
	sessions             map[coquic.ConnectionHandle]*session
	completedCRRSessions map[coquic.ConnectionHandle]bool
	acceptedSession      bool
	completedSessionSeen bool
}

func (s *Server) run() error {
	for {
		if err := s.handleDueTimer(); err != nil {
			return err
		}
		if s.shouldExitOnSessionComplete() || s.shouldExitOnIdleEmpty() {
			return nil
		}

		wakeup, hasWakeup := s.endpoint.NextWakeup()
		event, err := s.io.Wait(wakeup, hasWakeup, idleTimeout)
		if err != nil {
			return err
		}
		switch event.Kind {
		case perfio.WaitDatagram:
			now := s.io.NowUs()
			result, err := s.endpoint.ReceiveDatagram(s.io.InboundDatagram(event.Datagram), now)
			if err != nil {
				return err
			}
			if err := s.handleResult(result, now); err != nil {
				return err
			}
		case perfio.WaitTimer:
			now := s.io.NowUs()
			result, err := s.endpoint.TimerExpired(now)
			if err != nil {
				return err
			}
			if err := s.handleResult(result, now); err != nil {
				return err
			}
		case perfio.WaitIdle:
			if err := s.io.FlushSends(); err != nil {
				return err
			}
			if s.shouldExitOnIdleEmpty() || s.shouldExitOnSessionComplete() {
				return nil
			}
		}
	}
}

func (s *Server) handleDueTimer() error {
	for {
		wakeup, ok := s.endpoint.NextWakeup()
		if !ok {
			return nil
		}
		now := s.io.NowUs()
		if wakeup > now {
			return nil
		}
		result, err := s.endpoint.TimerExpired(now)
		if err != nil {
			return err
		}
		if err := s.handleResult(result, now); err != nil {
			return err
		}
	}
}

func (s *Server) handleResult(result *coquic.QueryResult, now coquic.TimeUs) error {
	pending := []*coquic.QueryResult{result}
	for index := 0; index < len(pending); index++ {
		current := pending[index]
		commands, err := s.collectResultCommands(current)
		current.Destroy()
		if err != nil {
			return err
		}
		for _, command := range commands {
			next, err := s.executeCommand(command, now)
			if err != nil {
				return err
			}
			pending = append(pending, next)
		}
	}
	return s.io.FlushSends()
}

func (s *Server) collectResultCommands(result *coquic.QueryResult) ([]serverCommand, error) {
	localError, err := result.LocalError()
	if err != nil {
		return nil, err
	}
	if localError != nil {
		return nil, fmt.Errorf("server local error: %+v", *localError)
	}

	if err := s.io.AppendResultSends(result); err != nil {
		return nil, err
	}
	effects, err := perfio.CopyNonSendEffects(result)
	if err != nil {
		return nil, err
	}

	commands := make([]serverCommand, 0)
	for _, effect := range effects {
		switch effect.Kind {
		case coquic.EffectConnectionLifecycleEvent:
			switch effect.Lifecycle {
			case coquic.LifecycleAccepted:
				s.acceptedSession = true
				s.sessions[effect.Connection] = &session{}
			case coquic.LifecycleClosed:
				current := s.sessions[effect.Connection]
				if current != nil &&
					current.start != nil &&
					current.start.Mode == config.ModeCRR &&
					current.requestsCompleted > 0 {
					s.completedCRRSessions[effect.Connection] = true
				}
				delete(s.sessions, effect.Connection)
			}
		case coquic.EffectStateEvent:
			if effect.StateChange == coquic.StateChangeFailed &&
				!s.tolerateFailedState(effect.Connection) {
				return nil, fmt.Errorf("server core state failed connection=%d", effect.Connection)
			}
		case coquic.EffectReceiveStreamData:
			next, err := s.handleStreamData(effect.Connection, effect.StreamID, effect.Bytes, effect.Fin)
			if err != nil {
				return nil, err
			}
			commands = append(commands, next...)
		}
	}
	return commands, nil
}

func (s *Server) handleStreamData(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	data []byte,
	fin bool,
) ([]serverCommand, error) {
	if uint64(streamID) == protocol.ControlStreamID {
		return s.handleControlStreamData(connection, data, fin)
	}

	current := s.sessions[connection]
	if current == nil || current.start == nil {
		return nil, nil
	}
	s.recordStreamData(current, data, fin)
	if !fin {
		return nil, nil
	}
	if current.start.Mode == config.ModeBulk {
		return s.handleBulkStreamFin(connection, streamID, current)
	}
	if current.start.Mode == config.ModeRR || current.start.Mode == config.ModeCRR {
		return s.handleRequestResponseFin(connection, streamID, current)
	}
	return nil, nil
}

func (s *Server) handleControlStreamData(
	connection coquic.ConnectionHandle,
	data []byte,
	fin bool,
) ([]serverCommand, error) {
	current := s.sessions[connection]
	if current == nil {
		return nil, fmt.Errorf("control stream for unknown session")
	}
	current.controlBytes = append(current.controlBytes, data...)
	if !fin {
		return nil, nil
	}

	decoded, ok := protocol.DecodeControlMessage(current.controlBytes)
	current.controlBytes = nil
	start, startOK := decoded.(protocol.SessionStart)
	if !ok || !startOK {
		return []serverCommand{s.sendControlCommand(connection, protocol.SessionError{Reason: "expected session_start"})}, nil
	}

	if reason := ValidateSessionStart(start); reason != "" {
		return []serverCommand{s.sendControlCommand(connection, protocol.SessionError{Reason: reason})}, nil
	}
	current.start = &start
	return []serverCommand{s.sendControlCommand(connection, protocol.SessionReady{ProtocolVersion: protocol.ProtocolVersion})}, nil
}

func (s *Server) recordStreamData(current *session, data []byte, fin bool) {
	current.bytesReceived += uint64(len(data))
	if fin {
		current.requestsCompleted++
	}
}

func (s *Server) handleBulkStreamFin(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	current *session,
) ([]serverCommand, error) {
	start := current.start
	if start == nil {
		return nil, nil
	}
	if start.Direction == config.DirectionDownload {
		return s.handleBulkDownloadFin(connection, streamID, current), nil
	}
	if start.TotalBytes != nil && current.requestsCompleted >= start.Streams {
		return s.completeSession(connection), nil
	}
	return nil, nil
}

func (s *Server) handleBulkDownloadFin(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	current *session,
) []serverCommand {
	start := current.start
	if start == nil {
		return nil
	}
	target := start.ResponseBytes
	commands := make([]serverCommand, 0, 2)
	if start.TotalBytes != nil {
		streamIndex := current.requestsCompleted - 1
		totalBytes := *start.TotalBytes
		perStream := totalBytes / start.Streams
		remainder := totalBytes % start.Streams
		target = perStream
		if streamIndex < remainder {
			target++
		}
	}
	commands = append(commands, serverCommand{
		kind:       commandSendResponse,
		connection: connection,
		streamID:   streamID,
		bytes:      target,
	})
	current.bytesSent += target
	if start.TotalBytes != nil && current.requestsCompleted >= start.Streams {
		commands = append(commands, s.completeSession(connection)...)
	}
	return commands
}

func (s *Server) handleRequestResponseFin(
	connection coquic.ConnectionHandle,
	streamID coquic.StreamID,
	current *session,
) ([]serverCommand, error) {
	start := current.start
	if start == nil {
		return nil, nil
	}
	commands := []serverCommand{{
		kind:       commandSendResponse,
		connection: connection,
		streamID:   streamID,
		bytes:      start.ResponseBytes,
	}}
	current.bytesSent += start.ResponseBytes
	if start.Mode == config.ModeRR &&
		start.Requests != nil &&
		current.requestsCompleted >= *start.Requests {
		commands = append(commands, s.completeSession(connection)...)
	}
	return commands, nil
}

func (s *Server) completeSession(connection coquic.ConnectionHandle) []serverCommand {
	command := s.makeCompleteCommand(connection)
	if command == nil {
		return nil
	}
	return []serverCommand{*command}
}

func (s *Server) executeCommand(command serverCommand, now coquic.TimeUs) (*coquic.QueryResult, error) {
	switch command.kind {
	case commandSendResponse:
		return s.endpoint.SendStream(command.connection, command.streamID, makePayload(command.bytes), true, now)
	case commandSendControl:
		fin := false
		switch command.message.(type) {
		case protocol.SessionError, protocol.SessionComplete:
			fin = true
		}
		payload := protocol.EncodeControlMessage(command.message)
		return s.endpoint.SendStream(command.connection, coquic.StreamID(protocol.ControlStreamID), payload, fin, now)
	default:
		return nil, fmt.Errorf("unknown server command")
	}
}

func (s *Server) makeCompleteCommand(connection coquic.ConnectionHandle) *serverCommand {
	current := s.sessions[connection]
	if current == nil || current.completeSent {
		return nil
	}
	current.completeSent = true
	s.completedSessionSeen = true
	command := s.sendControlCommand(connection, protocol.SessionComplete{
		BytesSent:         current.bytesSent,
		BytesReceived:     current.bytesReceived,
		RequestsCompleted: current.requestsCompleted,
	})
	return &command
}

func (s *Server) sendControlCommand(connection coquic.ConnectionHandle, message protocol.ControlMessage) serverCommand {
	return serverCommand{
		kind:       commandSendControl,
		connection: connection,
		message:    message,
	}
}

func (s *Server) shouldExitOnIdleEmpty() bool {
	return s.acceptedSession &&
		len(s.sessions) == 0 &&
		envFlagEnabled("COQUIC_PERF_SERVER_EXIT_ON_IDLE_EMPTY")
}

func (s *Server) shouldExitOnSessionComplete() bool {
	if !s.acceptedSession ||
		!s.completedSessionSeen ||
		!envFlagEnabled("COQUIC_PERF_SERVER_EXIT_ON_SESSION_COMPLETE") ||
		!s.io.SendBufferEmpty() ||
		s.endpoint.HasSendContinuationPending() ||
		s.endpoint.HasPendingStreamSend() {
		return false
	}
	for _, current := range s.sessions {
		if !current.completeSent {
			return false
		}
	}
	return true
}

func (s *Server) tolerateFailedState(connection coquic.ConnectionHandle) bool {
	current := s.sessions[connection]
	return s.completedCRRSessions[connection] ||
		(current != nil &&
			current.start != nil &&
			(current.start.Mode != config.ModeCRR || current.requestsCompleted > 0))
}

func ValidateSessionStart(start protocol.SessionStart) string {
	if start.ProtocolVersion != protocol.ProtocolVersion &&
		start.ProtocolVersion != protocol.ProtocolVersionLegacy {
		return "unsupported protocol version"
	}
	if start.Streams == 0 {
		return "streams must be greater than zero"
	}
	if start.Connections == 0 {
		return "connections must be greater than zero"
	}
	if start.RequestsInFlight == 0 {
		return "requests_in_flight must be greater than zero"
	}
	return ""
}

func makePayload(size uint64) []byte {
	payload := make([]byte, int(size))
	for index := range payload {
		payload[index] = 0x5a
	}
	return payload
}

func envFlagEnabled(name string) bool {
	value, ok := os.LookupEnv(name)
	return ok && value != "" && value != "0"
}
