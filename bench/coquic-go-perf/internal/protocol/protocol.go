package protocol

import (
	"encoding/binary"
	"time"

	"github.com/minhuw/coquic/bench/coquic-go-perf/internal/config"
)

const (
	ProtocolVersionLegacy       uint32 = 1
	ProtocolVersionMilliseconds uint32 = 2
	ProtocolVersion             uint32 = 3
	ControlStreamID             uint64 = 0
	FirstDataStreamID           uint64 = 4
)

const (
	messageSessionStart    byte = 1
	messageSessionReady    byte = 2
	messageSessionError    byte = 3
	messageSessionComplete byte = 4
)

const (
	optionalTotalBytesFlag byte = 0x01
	optionalRequestsFlag   byte = 0x02
)

type SessionStart struct {
	ProtocolVersion  uint32
	Mode             config.Mode
	Direction        config.Direction
	RequestBytes     uint64
	ResponseBytes    uint64
	TotalBytes       *uint64
	Requests         *uint64
	Warmup           time.Duration
	Duration         time.Duration
	Streams          uint64
	Connections      uint64
	RequestsInFlight uint64
}

type SessionReady struct {
	ProtocolVersion uint32
}

type SessionError struct {
	Reason string
}

type SessionComplete struct {
	BytesSent         uint64
	BytesReceived     uint64
	RequestsCompleted uint64
}

type ControlMessage interface{}

func EncodeControlMessage(message ControlMessage) []byte {
	payload := make([]byte, 0, 96)
	var messageType byte
	switch value := message.(type) {
	case SessionStart:
		appendU32(&payload, value.ProtocolVersion)
		appendU8(&payload, modeToU8(value.Mode))
		appendU8(&payload, directionToU8(value.Direction))
		appendU64(&payload, value.RequestBytes)
		appendU64(&payload, value.ResponseBytes)
		if value.ProtocolVersion != ProtocolVersionLegacy {
			appendU8(&payload, sessionStartOptionalFlags(value))
		}
		appendU64(&payload, optionalValue(value.TotalBytes))
		appendU64(&payload, optionalValue(value.Requests))
		if value.ProtocolVersion == ProtocolVersionLegacy ||
			value.ProtocolVersion == ProtocolVersionMilliseconds {
			appendU64(&payload, durationMillis(value.Warmup))
			appendU64(&payload, durationMillis(value.Duration))
		} else {
			appendU64(&payload, durationMicros(value.Warmup))
			appendU64(&payload, durationMicros(value.Duration))
		}
		appendU64(&payload, value.Streams)
		appendU64(&payload, value.Connections)
		appendU64(&payload, value.RequestsInFlight)
		messageType = messageSessionStart
	case SessionReady:
		appendU32(&payload, value.ProtocolVersion)
		messageType = messageSessionReady
	case SessionError:
		appendU32(&payload, uint32(len(value.Reason)))
		payload = append(payload, []byte(value.Reason)...)
		messageType = messageSessionError
	case SessionComplete:
		appendU64(&payload, value.BytesSent)
		appendU64(&payload, value.BytesReceived)
		appendU64(&payload, value.RequestsCompleted)
		messageType = messageSessionComplete
	default:
		return nil
	}

	out := make([]byte, 0, 5+len(payload))
	appendU8(&out, messageType)
	appendU32(&out, uint32(len(payload)))
	out = append(out, payload...)
	return out
}

func DecodeControlMessage(input []byte) (ControlMessage, bool) {
	messageType, input, ok := takeU8(input)
	if !ok {
		return nil, false
	}
	payloadSize, input, ok := takeU32(input)
	if !ok || len(input) != int(payloadSize) {
		return nil, false
	}

	switch messageType {
	case messageSessionStart:
		return decodeSessionStart(input)
	case messageSessionReady:
		protocolVersion, rest, ok := takeU32(input)
		if !ok || len(rest) != 0 {
			return nil, false
		}
		return SessionReady{ProtocolVersion: protocolVersion}, true
	case messageSessionError:
		reason, rest, ok := takeString(input)
		if !ok || len(rest) != 0 {
			return nil, false
		}
		return SessionError{Reason: reason}, true
	case messageSessionComplete:
		bytesSent, rest, ok := takeU64(input)
		if !ok {
			return nil, false
		}
		bytesReceived, rest, ok := takeU64(rest)
		if !ok {
			return nil, false
		}
		requestsCompleted, rest, ok := takeU64(rest)
		if !ok || len(rest) != 0 {
			return nil, false
		}
		return SessionComplete{
			BytesSent:         bytesSent,
			BytesReceived:     bytesReceived,
			RequestsCompleted: requestsCompleted,
		}, true
	default:
		return nil, false
	}
}

func TakeControlMessage(buffer *[]byte) (ControlMessage, bool) {
	if len(*buffer) < 5 {
		return nil, false
	}
	payloadSize := binary.BigEndian.Uint32((*buffer)[1:5])
	frameSize := 5 + int(payloadSize)
	if len(*buffer) < frameSize {
		return nil, false
	}
	frame := append([]byte(nil), (*buffer)[:frameSize]...)
	*buffer = (*buffer)[frameSize:]
	return DecodeControlMessage(frame)
}

func NextClientStreamID(current uint64) uint64 {
	if current == 0 {
		return FirstDataStreamID
	}
	return current + 4
}

func decodeSessionStart(input []byte) (ControlMessage, bool) {
	protocolVersion, input, ok := takeU32(input)
	if !ok {
		return nil, false
	}
	modeRaw, input, ok := takeU8(input)
	if !ok {
		return nil, false
	}
	mode, ok := parseMode(modeRaw)
	if !ok {
		return nil, false
	}
	directionRaw, input, ok := takeU8(input)
	if !ok {
		return nil, false
	}
	direction, ok := parseDirection(directionRaw)
	if !ok {
		return nil, false
	}
	requestBytes, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	responseBytes, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}

	var optionalFlags byte
	if protocolVersion == ProtocolVersion || protocolVersion == ProtocolVersionMilliseconds {
		optionalFlags, input, ok = takeU8(input)
		if !ok {
			return nil, false
		}
	} else if protocolVersion != ProtocolVersionLegacy {
		return nil, false
	}

	totalBytesRaw, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	requestsRaw, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	warmupRaw, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	durationRaw, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	streams, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	connections, input, ok := takeU64(input)
	if !ok {
		return nil, false
	}
	requestsInFlight, input, ok := takeU64(input)
	if !ok || len(input) != 0 {
		return nil, false
	}

	var totalBytes *uint64
	var requests *uint64
	if protocolVersion == ProtocolVersionLegacy {
		if totalBytesRaw != 0 {
			totalBytes = ptr(totalBytesRaw)
		}
		if requestsRaw != 0 {
			requests = ptr(requestsRaw)
		}
	} else {
		if optionalFlags&optionalTotalBytesFlag != 0 {
			totalBytes = ptr(totalBytesRaw)
		}
		if optionalFlags&optionalRequestsFlag != 0 {
			requests = ptr(requestsRaw)
		}
	}

	warmup := time.Duration(warmupRaw) * time.Microsecond
	duration := time.Duration(durationRaw) * time.Microsecond
	if protocolVersion == ProtocolVersionLegacy ||
		protocolVersion == ProtocolVersionMilliseconds {
		warmup = time.Duration(warmupRaw) * time.Millisecond
		duration = time.Duration(durationRaw) * time.Millisecond
	}

	return SessionStart{
		ProtocolVersion:  protocolVersion,
		Mode:             mode,
		Direction:        direction,
		RequestBytes:     requestBytes,
		ResponseBytes:    responseBytes,
		TotalBytes:       totalBytes,
		Requests:         requests,
		Warmup:           warmup,
		Duration:         duration,
		Streams:          streams,
		Connections:      connections,
		RequestsInFlight: requestsInFlight,
	}, true
}

func appendU8(out *[]byte, value byte) {
	*out = append(*out, value)
}

func appendU32(out *[]byte, value uint32) {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	*out = append(*out, bytes[:]...)
}

func appendU64(out *[]byte, value uint64) {
	var bytes [8]byte
	binary.BigEndian.PutUint64(bytes[:], value)
	*out = append(*out, bytes[:]...)
}

func takeU8(input []byte) (byte, []byte, bool) {
	if len(input) < 1 {
		return 0, input, false
	}
	return input[0], input[1:], true
}

func takeU32(input []byte) (uint32, []byte, bool) {
	if len(input) < 4 {
		return 0, input, false
	}
	return binary.BigEndian.Uint32(input[:4]), input[4:], true
}

func takeU64(input []byte) (uint64, []byte, bool) {
	if len(input) < 8 {
		return 0, input, false
	}
	return binary.BigEndian.Uint64(input[:8]), input[8:], true
}

func takeString(input []byte) (string, []byte, bool) {
	size, input, ok := takeU32(input)
	if !ok || len(input) < int(size) {
		return "", input, false
	}
	return string(input[:size]), input[size:], true
}

func modeToU8(mode config.Mode) byte {
	switch mode {
	case config.ModeBulk:
		return 0
	case config.ModeRR:
		return 1
	case config.ModeCRR:
		return 2
	case config.ModePersistentRR:
		return 3
	default:
		return 0
	}
}

func parseMode(value byte) (config.Mode, bool) {
	switch value {
	case 0:
		return config.ModeBulk, true
	case 1:
		return config.ModeRR, true
	case 2:
		return config.ModeCRR, true
	case 3:
		return config.ModePersistentRR, true
	default:
		return 0, false
	}
}

func directionToU8(direction config.Direction) byte {
	switch direction {
	case config.DirectionUpload:
		return 0
	case config.DirectionDownload:
		return 1
	default:
		return 0
	}
}

func parseDirection(value byte) (config.Direction, bool) {
	switch value {
	case 0:
		return config.DirectionUpload, true
	case 1:
		return config.DirectionDownload, true
	default:
		return 0, false
	}
}

func sessionStartOptionalFlags(start SessionStart) byte {
	var flags byte
	if start.TotalBytes != nil {
		flags |= optionalTotalBytesFlag
	}
	if start.Requests != nil {
		flags |= optionalRequestsFlag
	}
	return flags
}

func optionalValue(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func durationMicros(duration time.Duration) uint64 {
	return uint64(duration / time.Microsecond)
}

func durationMillis(duration time.Duration) uint64 {
	return uint64(duration / time.Millisecond)
}

func ptr(value uint64) *uint64 {
	return &value
}
