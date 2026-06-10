use crate::config::{Direction, Mode};
use std::time::Duration;

pub const PROTOCOL_VERSION_LEGACY: u32 = 1;
pub const PROTOCOL_VERSION_MILLISECONDS: u32 = 2;
pub const PROTOCOL_VERSION: u32 = 3;
pub const CONTROL_STREAM_ID: u64 = 0;
pub const FIRST_DATA_STREAM_ID: u64 = 4;

const MESSAGE_SESSION_START: u8 = 1;
const MESSAGE_SESSION_READY: u8 = 2;
const MESSAGE_SESSION_ERROR: u8 = 3;
const MESSAGE_SESSION_COMPLETE: u8 = 4;

const OPTIONAL_TOTAL_BYTES_FLAG: u8 = 0x01;
const OPTIONAL_REQUESTS_FLAG: u8 = 0x02;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStart {
    pub protocol_version: u32,
    pub mode: Mode,
    pub direction: Direction,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub total_bytes: Option<u64>,
    pub requests: Option<u64>,
    pub warmup: Duration,
    pub duration: Duration,
    pub streams: u64,
    pub connections: u64,
    pub requests_in_flight: u64,
}

impl Default for SessionStart {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            mode: Mode::Bulk,
            direction: Direction::Download,
            request_bytes: 0,
            response_bytes: 0,
            total_bytes: None,
            requests: None,
            warmup: Duration::ZERO,
            duration: Duration::ZERO,
            streams: 1,
            connections: 1,
            requests_in_flight: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReady {
    pub protocol_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionError {
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionComplete {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_completed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    SessionStart(SessionStart),
    SessionReady(SessionReady),
    SessionError(SessionError),
    SessionComplete(SessionComplete),
}

pub fn encode_control_message(message: &ControlMessage) -> Vec<u8> {
    let mut payload = Vec::new();
    let message_type = match message {
        ControlMessage::SessionStart(start) => {
            append_u32(&mut payload, start.protocol_version);
            append_u8(&mut payload, mode_to_u8(start.mode));
            append_u8(&mut payload, direction_to_u8(start.direction));
            append_u64(&mut payload, start.request_bytes);
            append_u64(&mut payload, start.response_bytes);
            if start.protocol_version != PROTOCOL_VERSION_LEGACY {
                append_u8(&mut payload, session_start_optional_flags(start));
            }
            append_u64(&mut payload, start.total_bytes.unwrap_or(0));
            append_u64(&mut payload, start.requests.unwrap_or(0));
            if start.protocol_version == PROTOCOL_VERSION_LEGACY
                || start.protocol_version == PROTOCOL_VERSION_MILLISECONDS
            {
                append_u64(&mut payload, duration_millis(start.warmup));
                append_u64(&mut payload, duration_millis(start.duration));
            } else {
                append_u64(&mut payload, duration_micros(start.warmup));
                append_u64(&mut payload, duration_micros(start.duration));
            }
            append_u64(&mut payload, start.streams);
            append_u64(&mut payload, start.connections);
            append_u64(&mut payload, start.requests_in_flight);
            MESSAGE_SESSION_START
        }
        ControlMessage::SessionReady(ready) => {
            append_u32(&mut payload, ready.protocol_version);
            MESSAGE_SESSION_READY
        }
        ControlMessage::SessionError(error) => {
            append_u32(&mut payload, error.reason.len() as u32);
            payload.extend_from_slice(error.reason.as_bytes());
            MESSAGE_SESSION_ERROR
        }
        ControlMessage::SessionComplete(complete) => {
            append_u64(&mut payload, complete.bytes_sent);
            append_u64(&mut payload, complete.bytes_received);
            append_u64(&mut payload, complete.requests_completed);
            MESSAGE_SESSION_COMPLETE
        }
    };

    let mut out = Vec::with_capacity(5 + payload.len());
    append_u8(&mut out, message_type);
    append_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(&payload);
    out
}

pub fn decode_control_message(mut input: &[u8]) -> Option<ControlMessage> {
    let message_type = take_u8(&mut input)?;
    let payload_size = take_u32(&mut input)? as usize;
    if input.len() != payload_size {
        return None;
    }

    match message_type {
        MESSAGE_SESSION_START => decode_session_start(input).map(ControlMessage::SessionStart),
        MESSAGE_SESSION_READY => {
            let protocol_version = take_u32(&mut input)?;
            input
                .is_empty()
                .then_some(ControlMessage::SessionReady(SessionReady {
                    protocol_version,
                }))
        }
        MESSAGE_SESSION_ERROR => {
            let reason = take_string(&mut input)?;
            input
                .is_empty()
                .then_some(ControlMessage::SessionError(SessionError { reason }))
        }
        MESSAGE_SESSION_COMPLETE => {
            let bytes_sent = take_u64(&mut input)?;
            let bytes_received = take_u64(&mut input)?;
            let requests_completed = take_u64(&mut input)?;
            input
                .is_empty()
                .then_some(ControlMessage::SessionComplete(SessionComplete {
                    bytes_sent,
                    bytes_received,
                    requests_completed,
                }))
        }
        _ => None,
    }
}

pub fn take_control_message(buffer: &mut Vec<u8>) -> Option<ControlMessage> {
    if buffer.len() < 5 {
        return None;
    }

    let payload_size = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    let frame_size = 5 + payload_size;
    if buffer.len() < frame_size {
        return None;
    }

    let frame: Vec<u8> = buffer.drain(..frame_size).collect();
    decode_control_message(&frame)
}

pub fn next_client_stream_id(current: u64) -> u64 {
    if current == 0 {
        FIRST_DATA_STREAM_ID
    } else {
        current + 4
    }
}

fn decode_session_start(mut input: &[u8]) -> Option<SessionStart> {
    let protocol_version = take_u32(&mut input)?;
    let mode = parse_mode(take_u8(&mut input)?)?;
    let direction = parse_direction(take_u8(&mut input)?)?;
    let request_bytes = take_u64(&mut input)?;
    let response_bytes = take_u64(&mut input)?;

    let optional_flags = if protocol_version == PROTOCOL_VERSION
        || protocol_version == PROTOCOL_VERSION_MILLISECONDS
    {
        take_u8(&mut input)?
    } else if protocol_version == PROTOCOL_VERSION_LEGACY {
        0
    } else {
        return None;
    };

    let total_bytes_raw = take_u64(&mut input)?;
    let requests_raw = take_u64(&mut input)?;
    let warmup_raw = take_u64(&mut input)?;
    let duration_raw = take_u64(&mut input)?;
    let streams = take_u64(&mut input)?;
    let connections = take_u64(&mut input)?;
    let requests_in_flight = take_u64(&mut input)?;
    if !input.is_empty() {
        return None;
    }

    let (total_bytes, requests) = if protocol_version == PROTOCOL_VERSION_LEGACY {
        (
            (total_bytes_raw != 0).then_some(total_bytes_raw),
            (requests_raw != 0).then_some(requests_raw),
        )
    } else {
        (
            ((optional_flags & OPTIONAL_TOTAL_BYTES_FLAG) != 0).then_some(total_bytes_raw),
            ((optional_flags & OPTIONAL_REQUESTS_FLAG) != 0).then_some(requests_raw),
        )
    };

    let (warmup, duration) = if protocol_version == PROTOCOL_VERSION_LEGACY
        || protocol_version == PROTOCOL_VERSION_MILLISECONDS
    {
        (
            Duration::from_millis(warmup_raw),
            Duration::from_millis(duration_raw),
        )
    } else {
        (
            Duration::from_micros(warmup_raw),
            Duration::from_micros(duration_raw),
        )
    };

    Some(SessionStart {
        protocol_version,
        mode,
        direction,
        request_bytes,
        response_bytes,
        total_bytes,
        requests,
        warmup,
        duration,
        streams,
        connections,
        requests_in_flight,
    })
}

fn append_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn take_u8(input: &mut &[u8]) -> Option<u8> {
    let (head, tail) = input.split_first()?;
    *input = tail;
    Some(*head)
}

fn take_u32(input: &mut &[u8]) -> Option<u32> {
    if input.len() < 4 {
        return None;
    }
    let value = u32::from_be_bytes(input[..4].try_into().ok()?);
    *input = &input[4..];
    Some(value)
}

fn take_u64(input: &mut &[u8]) -> Option<u64> {
    if input.len() < 8 {
        return None;
    }
    let value = u64::from_be_bytes(input[..8].try_into().ok()?);
    *input = &input[8..];
    Some(value)
}

fn take_string(input: &mut &[u8]) -> Option<String> {
    let size = take_u32(input)? as usize;
    if input.len() < size {
        return None;
    }
    let value = String::from_utf8(input[..size].to_vec()).ok()?;
    *input = &input[size..];
    Some(value)
}

fn mode_to_u8(mode: Mode) -> u8 {
    match mode {
        Mode::Bulk => 0,
        Mode::Rr => 1,
        Mode::Crr => 2,
        Mode::PersistentRr => 3,
    }
}

fn parse_mode(value: u8) -> Option<Mode> {
    match value {
        0 => Some(Mode::Bulk),
        1 => Some(Mode::Rr),
        2 => Some(Mode::Crr),
        3 => Some(Mode::PersistentRr),
        _ => None,
    }
}

fn direction_to_u8(direction: Direction) -> u8 {
    match direction {
        Direction::Upload => 0,
        Direction::Download => 1,
    }
}

fn parse_direction(value: u8) -> Option<Direction> {
    match value {
        0 => Some(Direction::Upload),
        1 => Some(Direction::Download),
        _ => None,
    }
}

fn session_start_optional_flags(start: &SessionStart) -> u8 {
    let mut flags = 0;
    if start.total_bytes.is_some() {
        flags |= OPTIONAL_TOTAL_BYTES_FLAG;
    }
    if start.requests.is_some() {
        flags |= OPTIONAL_REQUESTS_FLAG;
    }
    flags
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_v3_session_start() {
        let start = SessionStart {
            protocol_version: PROTOCOL_VERSION,
            mode: Mode::Rr,
            direction: Direction::Download,
            request_bytes: 64,
            response_bytes: 128,
            total_bytes: Some(1024),
            requests: Some(10),
            warmup: Duration::from_millis(250),
            duration: Duration::from_secs(2),
            streams: 4,
            connections: 2,
            requests_in_flight: 3,
        };
        let message = ControlMessage::SessionStart(start.clone());
        let encoded = encode_control_message(&message);
        assert_eq!(decode_control_message(&encoded), Some(message));
    }

    #[test]
    fn take_control_message_waits_for_complete_frame() {
        let encoded = encode_control_message(&ControlMessage::SessionReady(SessionReady {
            protocol_version: PROTOCOL_VERSION,
        }));
        let mut partial = encoded[..encoded.len() - 1].to_vec();
        assert_eq!(take_control_message(&mut partial), None);

        let mut complete = encoded;
        assert_eq!(
            take_control_message(&mut complete),
            Some(ControlMessage::SessionReady(SessionReady {
                protocol_version: PROTOCOL_VERSION
            }))
        );
        assert!(complete.is_empty());
    }

    #[test]
    fn next_client_stream_ids_match_perf_layout() {
        assert_eq!(next_client_stream_id(0), 4);
        assert_eq!(next_client_stream_id(4), 8);
    }
}
