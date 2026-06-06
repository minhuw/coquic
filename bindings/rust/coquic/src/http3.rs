use crate::ffi;
use crate::{
    bytes, bytes_view, optional_stream_from_raw, optional_u64, optional_u64_from_raw,
    ConnectionInput, QueryResult, Status, StreamId, TimeUs,
};
use std::error::Error;
use std::ffi::c_char;
use std::fmt;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    NoError,
    GeneralProtocolError,
    InternalError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    RequestRejected,
    RequestCancelled,
    RequestIncomplete,
    MessageError,
    VersionFallback,
    QpackDecompressionFailed,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
    Unknown(u16),
}

impl ErrorCode {
    fn from_raw(raw: ffi::coquic_http3_error_code_t) -> Self {
        match raw {
            ffi::COQUIC_HTTP3_ERROR_NO_ERROR => Self::NoError,
            ffi::COQUIC_HTTP3_ERROR_GENERAL_PROTOCOL_ERROR => Self::GeneralProtocolError,
            ffi::COQUIC_HTTP3_ERROR_INTERNAL_ERROR => Self::InternalError,
            ffi::COQUIC_HTTP3_ERROR_STREAM_CREATION_ERROR => Self::StreamCreationError,
            ffi::COQUIC_HTTP3_ERROR_CLOSED_CRITICAL_STREAM => Self::ClosedCriticalStream,
            ffi::COQUIC_HTTP3_ERROR_FRAME_UNEXPECTED => Self::FrameUnexpected,
            ffi::COQUIC_HTTP3_ERROR_FRAME_ERROR => Self::FrameError,
            ffi::COQUIC_HTTP3_ERROR_EXCESSIVE_LOAD => Self::ExcessiveLoad,
            ffi::COQUIC_HTTP3_ERROR_ID_ERROR => Self::IdError,
            ffi::COQUIC_HTTP3_ERROR_SETTINGS_ERROR => Self::SettingsError,
            ffi::COQUIC_HTTP3_ERROR_MISSING_SETTINGS => Self::MissingSettings,
            ffi::COQUIC_HTTP3_ERROR_REQUEST_REJECTED => Self::RequestRejected,
            ffi::COQUIC_HTTP3_ERROR_REQUEST_CANCELLED => Self::RequestCancelled,
            ffi::COQUIC_HTTP3_ERROR_REQUEST_INCOMPLETE => Self::RequestIncomplete,
            ffi::COQUIC_HTTP3_ERROR_MESSAGE_ERROR => Self::MessageError,
            ffi::COQUIC_HTTP3_ERROR_VERSION_FALLBACK => Self::VersionFallback,
            ffi::COQUIC_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED => Self::QpackDecompressionFailed,
            ffi::COQUIC_HTTP3_ERROR_QPACK_ENCODER_STREAM_ERROR => Self::QpackEncoderStreamError,
            ffi::COQUIC_HTTP3_ERROR_QPACK_DECODER_STREAM_ERROR => Self::QpackDecoderStreamError,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
    pub max_field_section_size: Option<u64>,
}

impl Settings {
    fn from_raw(raw: ffi::coquic_http3_settings_t) -> Self {
        Self {
            qpack_max_table_capacity: raw.qpack_max_table_capacity,
            qpack_blocked_streams: raw.qpack_blocked_streams,
            max_field_section_size: optional_u64_from_raw(raw.max_field_section_size),
        }
    }

    fn to_raw(&self) -> ffi::coquic_http3_settings_t {
        ffi::coquic_http3_settings_t {
            size: std::mem::size_of::<ffi::coquic_http3_settings_t>(),
            qpack_max_table_capacity: self.qpack_max_table_capacity,
            qpack_blocked_streams: self.qpack_blocked_streams,
            max_field_section_size: optional_u64(self.max_field_section_size),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_http3_settings_t>::uninit();
        unsafe {
            ffi::coquic_http3_settings_init(raw.as_mut_ptr());
            Self::from_raw(raw.assume_init())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub local_settings: Settings,
}

impl ClientConfig {
    fn to_raw(&self) -> ffi::coquic_http3_client_config_t {
        ffi::coquic_http3_client_config_t {
            size: std::mem::size_of::<ffi::coquic_http3_client_config_t>(),
            local_settings: self.local_settings.to_raw(),
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_http3_client_config_t>::uninit();
        unsafe {
            ffi::coquic_http3_client_config_init(raw.as_mut_ptr());
            let raw = raw.assume_init();
            Self {
                local_settings: Settings::from_raw(raw.local_settings),
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub local_settings: Settings,
}

impl ServerConfig {
    fn to_raw(&self) -> ffi::coquic_http3_server_config_t {
        ffi::coquic_http3_server_config_t {
            size: std::mem::size_of::<ffi::coquic_http3_server_config_t>(),
            local_settings: self.local_settings.to_raw(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let mut raw = MaybeUninit::<ffi::coquic_http3_server_config_t>::uninit();
        unsafe {
            ffi::coquic_http3_server_config_init(raw.as_mut_ptr());
            let raw = raw.assume_init();
            Self {
                local_settings: Settings::from_raw(raw.local_settings),
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Field {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    fn to_raw(&self) -> ffi::coquic_http3_field_t {
        ffi::coquic_http3_field_t {
            name: self.name.as_ptr().cast::<c_char>(),
            name_length: self.name.len(),
            value: self.value.as_ptr().cast::<c_char>(),
            value_length: self.value.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldView<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> FieldView<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_field_view_t) -> Self {
        Self {
            name: unsafe { bytes_view(raw.name) },
            value: unsafe { bytes_view(raw.value) },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHead {
    pub method: Vec<u8>,
    pub scheme: Vec<u8>,
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
    pub content_length: Option<u64>,
    pub headers: Vec<Field>,
}

impl RequestHead {
    pub fn get(authority: impl Into<Vec<u8>>, path: impl Into<Vec<u8>>) -> Self {
        Self {
            method: b"GET".to_vec(),
            scheme: b"https".to_vec(),
            authority: authority.into(),
            path: path.into(),
            content_length: None,
            headers: Vec::new(),
        }
    }

    fn materialize(&self) -> MaterializedRequestHead<'_> {
        MaterializedRequestHead {
            headers: self.headers.iter().map(Field::to_raw).collect(),
            raw: ffi::coquic_http3_request_head_t {
                size: std::mem::size_of::<ffi::coquic_http3_request_head_t>(),
                method: self.method.as_ptr().cast::<c_char>(),
                method_length: self.method.len(),
                scheme: self.scheme.as_ptr().cast::<c_char>(),
                scheme_length: self.scheme.len(),
                authority: self.authority.as_ptr().cast::<c_char>(),
                authority_length: self.authority.len(),
                path: self.path.as_ptr().cast::<c_char>(),
                path_length: self.path.len(),
                content_length: optional_u64(self.content_length),
                headers: std::ptr::null(),
                headers_count: 0,
            },
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RequestHeadView<'a> {
    raw: ffi::coquic_http3_request_head_view_t,
    _marker: PhantomData<&'a ffi::coquic_http3_request_head_view_t>,
}

impl<'a> RequestHeadView<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_request_head_view_t) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn method(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.method) }
    }

    pub fn scheme(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.scheme) }
    }

    pub fn authority(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.authority) }
    }

    pub fn path(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.path) }
    }

    pub fn content_length(&self) -> Option<u64> {
        optional_u64_from_raw(self.raw.content_length)
    }

    pub fn header_count(&self) -> usize {
        self.raw.headers_count
    }

    pub fn header(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_request_head_view_header_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }
}

struct MaterializedRequestHead<'a> {
    headers: Vec<ffi::coquic_http3_field_t>,
    raw: ffi::coquic_http3_request_head_t,
    _marker: PhantomData<&'a RequestHead>,
}

impl MaterializedRequestHead<'_> {
    fn as_raw(&mut self) -> ffi::coquic_http3_request_head_t {
        self.raw.headers = self.headers.as_ptr();
        self.raw.headers_count = self.headers.len();
        self.raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub head: RequestHead,
    pub body: Vec<u8>,
    pub trailers: Vec<Field>,
}

impl Request {
    pub fn new(head: RequestHead) -> Self {
        Self {
            head,
            body: Vec::new(),
            trailers: Vec::new(),
        }
    }

    fn materialize(&self) -> MaterializedRequest<'_> {
        MaterializedRequest {
            head: self.head.materialize(),
            trailers: self.trailers.iter().map(Field::to_raw).collect(),
            raw: ffi::coquic_http3_request_t {
                size: std::mem::size_of::<ffi::coquic_http3_request_t>(),
                head: ffi::coquic_http3_request_head_t {
                    size: 0,
                    method: std::ptr::null(),
                    method_length: 0,
                    scheme: std::ptr::null(),
                    scheme_length: 0,
                    authority: std::ptr::null(),
                    authority_length: 0,
                    path: std::ptr::null(),
                    path_length: 0,
                    content_length: ffi::coquic_http3_optional_u64_t::none(),
                    headers: std::ptr::null(),
                    headers_count: 0,
                },
                body: bytes(self.body.as_slice()),
                trailers: std::ptr::null(),
                trailers_count: 0,
            },
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RequestView<'a> {
    raw: ffi::coquic_http3_request_view_t,
    _marker: PhantomData<&'a ffi::coquic_http3_request_view_t>,
}

impl<'a> RequestView<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_request_view_t) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn head(&self) -> RequestHeadView<'a> {
        unsafe { RequestHeadView::from_raw(self.raw.head) }
    }

    pub fn body(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.body) }
    }

    pub fn trailer_count(&self) -> usize {
        self.raw.trailers_count
    }

    pub fn trailer(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_request_view_trailer_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }

    pub fn header(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_request_view_header_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }
}

struct MaterializedRequest<'a> {
    head: MaterializedRequestHead<'a>,
    trailers: Vec<ffi::coquic_http3_field_t>,
    raw: ffi::coquic_http3_request_t,
    _marker: PhantomData<&'a Request>,
}

impl MaterializedRequest<'_> {
    fn as_raw(&mut self) -> *const ffi::coquic_http3_request_t {
        self.raw.head = self.head.as_raw();
        self.raw.trailers = self.trailers.as_ptr();
        self.raw.trailers_count = self.trailers.len();
        &self.raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHead {
    pub status: u16,
    pub content_length: Option<u64>,
    pub headers: Vec<Field>,
}

#[derive(Clone, Copy, Debug)]
pub struct ResponseHeadView<'a> {
    raw: ffi::coquic_http3_response_head_view_t,
    _marker: PhantomData<&'a ffi::coquic_http3_response_head_view_t>,
}

impl<'a> ResponseHeadView<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_response_head_view_t) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn status(&self) -> u16 {
        self.raw.status
    }

    pub fn content_length(&self) -> Option<u64> {
        optional_u64_from_raw(self.raw.content_length)
    }

    pub fn header_count(&self) -> usize {
        self.raw.headers_count
    }

    pub fn header(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_response_head_view_header_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ResponseView<'a> {
    raw: ffi::coquic_http3_response_view_t,
    _marker: PhantomData<&'a ffi::coquic_http3_response_view_t>,
}

impl<'a> ResponseView<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_response_view_t) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn interim_head_count(&self) -> usize {
        self.raw.interim_head_count
    }

    pub fn interim_head(&self, index: usize) -> Result<ResponseHeadView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_response_head_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_response_view_interim_head_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(ResponseHeadView::from_raw(out.assume_init()))
        }
    }

    pub fn head(&self) -> ResponseHeadView<'a> {
        unsafe { ResponseHeadView::from_raw(self.raw.head) }
    }

    pub fn body(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.body) }
    }

    pub fn header(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_response_view_header_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }

    pub fn trailer_count(&self) -> usize {
        self.raw.trailers_count
    }

    pub fn trailer(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_response_view_trailer_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClientResponseEvent<'a> {
    pub stream_id: StreamId,
    pub request: RequestView<'a>,
    pub response: ResponseView<'a>,
}

impl<'a> ClientResponseEvent<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_client_response_event_t) -> Self {
        Self {
            stream_id: raw.stream_id,
            request: unsafe { RequestView::from_raw(raw.request) },
            response: unsafe { ResponseView::from_raw(raw.response) },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClientRequestErrorEvent<'a> {
    pub stream_id: StreamId,
    pub request: RequestView<'a>,
    pub application_error_code: u64,
}

impl<'a> ClientRequestErrorEvent<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_client_request_error_event_t) -> Self {
        Self {
            stream_id: raw.stream_id,
            request: unsafe { RequestView::from_raw(raw.request) },
            application_error_code: raw.application_error_code,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ServerRequestCancelledEvent<'a> {
    raw: ffi::coquic_http3_server_request_cancelled_event_t,
    _marker: PhantomData<&'a ffi::coquic_http3_server_request_cancelled_event_t>,
}

impl<'a> ServerRequestCancelledEvent<'a> {
    unsafe fn from_raw(raw: ffi::coquic_http3_server_request_cancelled_event_t) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.raw.stream_id
    }

    pub fn head(&self) -> Option<RequestHeadView<'a>> {
        (self.raw.has_head != 0).then(|| unsafe { RequestHeadView::from_raw(self.raw.head) })
    }

    pub fn body(&self) -> &'a [u8] {
        unsafe { bytes_view(self.raw.body) }
    }

    pub fn trailer_count(&self) -> usize {
        self.raw.trailers_count
    }

    pub fn trailer(&self, index: usize) -> Result<FieldView<'a>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_field_view_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_request_cancelled_view_trailer_at(
                &self.raw,
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(FieldView::from_raw(out.assume_init()))
        }
    }

    pub fn application_error_code(&self) -> u64 {
        self.raw.application_error_code
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3Error {
    pub code: ErrorCode,
    pub stream_id: Option<StreamId>,
    pub detail: Vec<u8>,
    pub detail_truncated: bool,
}

impl fmt::Display for Http3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", String::from_utf8_lossy(&self.detail))?;
        }
        Ok(())
    }
}

impl Error for Http3Error {}

#[derive(Debug)]
pub enum SubmitRequestError {
    Ffi(Status),
    Http3(Http3Error),
}

impl fmt::Display for SubmitRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ffi(status) => write!(f, "FFI error: {status}"),
            Self::Http3(error) => write!(f, "HTTP/3 error: {error}"),
        }
    }
}

impl Error for SubmitRequestError {}

pub struct Client {
    ptr: NonNull<ffi::coquic_http3_client_t>,
}

impl Client {
    pub fn new(config: &ClientConfig) -> Result<Self, Status> {
        let raw = config.to_raw();
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_create(&raw, &mut out))?;
        }
        let ptr = NonNull::new(out).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub fn submit_request(&mut self, request: &Request) -> Result<StreamId, SubmitRequestError> {
        let mut request = request.materialize();
        let mut stream_id = 0;
        let mut detail = vec![0u8; 512];
        let mut error = ffi::coquic_http3_error_t {
            detail_buffer: detail.as_mut_ptr().cast::<c_char>(),
            detail_buffer_capacity: detail.len(),
            ..Default::default()
        };

        let status = unsafe {
            ffi::coquic_http3_client_submit_request(
                self.ptr.as_ptr(),
                request.as_raw(),
                &mut stream_id,
                &mut error,
            )
        };
        Status::into_result(status).map_err(SubmitRequestError::Ffi)?;

        if error.code != ffi::COQUIC_HTTP3_ERROR_NO_ERROR {
            let copied = error.detail_length.min(detail.len());
            detail.truncate(copied);
            return Err(SubmitRequestError::Http3(Http3Error {
                code: ErrorCode::from_raw(error.code),
                stream_id: optional_stream_from_raw(error.stream_id),
                detail,
                detail_truncated: error.detail_truncated != 0,
            }));
        }

        Ok(stream_id)
    }

    pub fn on_quic_result(
        &mut self,
        result: &QueryResult,
        now: TimeUs,
    ) -> Result<ClientUpdate, Status> {
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_on_quic_result(
                self.ptr.as_ptr(),
                result.as_raw(),
                now,
                &mut out,
            ))?;
        }
        ClientUpdate::from_raw(out)
    }

    pub fn poll(&mut self, now: TimeUs) -> Result<ClientUpdate, Status> {
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_poll(
                self.ptr.as_ptr(),
                now,
                &mut out,
            ))?;
        }
        ClientUpdate::from_raw(out)
    }

    pub fn has_failed(&self) -> bool {
        unsafe { ffi::coquic_http3_client_has_failed(self.ptr.as_ptr()) != 0 }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_http3_client_destroy(self.ptr.as_ptr());
        }
    }
}

pub struct ClientUpdate {
    ptr: NonNull<ffi::coquic_http3_client_update_t>,
}

impl ClientUpdate {
    fn from_raw(ptr: *mut ffi::coquic_http3_client_update_t) -> Result<Self, Status> {
        let ptr = NonNull::new(ptr).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub fn connection_input_count(&self) -> usize {
        unsafe { ffi::coquic_http3_client_update_connection_input_count(self.ptr.as_ptr()) }
    }

    pub fn connection_input(&self, index: usize) -> Result<ConnectionInput<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_connection_input_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_update_connection_input_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            connection_input_from_raw(out.assume_init())
        }
    }

    pub fn response_count(&self) -> usize {
        unsafe { ffi::coquic_http3_client_update_response_count(self.ptr.as_ptr()) }
    }

    pub fn response(&self, index: usize) -> Result<ClientResponseEvent<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_client_response_event_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_update_response_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(ClientResponseEvent::from_raw(out.assume_init()))
        }
    }

    pub fn request_error_count(&self) -> usize {
        unsafe { ffi::coquic_http3_client_update_request_error_count(self.ptr.as_ptr()) }
    }

    pub fn request_error(&self, index: usize) -> Result<ClientRequestErrorEvent<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_client_request_error_event_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_client_update_request_error_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(ClientRequestErrorEvent::from_raw(out.assume_init()))
        }
    }

    pub fn has_pending_work(&self) -> bool {
        unsafe { ffi::coquic_http3_client_update_has_pending_work(self.ptr.as_ptr()) != 0 }
    }

    pub fn terminal_failure(&self) -> bool {
        unsafe { ffi::coquic_http3_client_update_terminal_failure(self.ptr.as_ptr()) != 0 }
    }

    pub fn handled_local_error(&self) -> bool {
        unsafe { ffi::coquic_http3_client_update_handled_local_error(self.ptr.as_ptr()) != 0 }
    }
}

impl Drop for ClientUpdate {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_http3_client_update_destroy(self.ptr.as_ptr());
        }
    }
}

pub struct Server {
    ptr: NonNull<ffi::coquic_http3_server_t>,
}

impl Server {
    pub fn new(config: &ServerConfig) -> Result<Self, Status> {
        let raw = config.to_raw();
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_create(&raw, &mut out))?;
        }
        let ptr = NonNull::new(out).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub fn on_quic_result(
        &mut self,
        result: &QueryResult,
        now: TimeUs,
    ) -> Result<ServerUpdate, Status> {
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_on_quic_result(
                self.ptr.as_ptr(),
                result.as_raw(),
                now,
                &mut out,
            ))?;
        }
        ServerUpdate::from_raw(out)
    }

    pub fn poll(&mut self, now: TimeUs) -> Result<ServerUpdate, Status> {
        let mut out = std::ptr::null_mut();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_poll(
                self.ptr.as_ptr(),
                now,
                &mut out,
            ))?;
        }
        ServerUpdate::from_raw(out)
    }

    pub fn has_failed(&self) -> bool {
        unsafe { ffi::coquic_http3_server_has_failed(self.ptr.as_ptr()) != 0 }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_http3_server_destroy(self.ptr.as_ptr());
        }
    }
}

pub struct ServerUpdate {
    ptr: NonNull<ffi::coquic_http3_server_update_t>,
}

impl ServerUpdate {
    fn from_raw(ptr: *mut ffi::coquic_http3_server_update_t) -> Result<Self, Status> {
        let ptr = NonNull::new(ptr).ok_or(Status::InternalError)?;
        Ok(Self { ptr })
    }

    pub fn connection_input_count(&self) -> usize {
        unsafe { ffi::coquic_http3_server_update_connection_input_count(self.ptr.as_ptr()) }
    }

    pub fn connection_input(&self, index: usize) -> Result<ConnectionInput<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_connection_input_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_update_connection_input_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            connection_input_from_raw(out.assume_init())
        }
    }

    pub fn request_cancelled_count(&self) -> usize {
        unsafe { ffi::coquic_http3_server_update_request_cancelled_count(self.ptr.as_ptr()) }
    }

    pub fn request_cancelled(
        &self,
        index: usize,
    ) -> Result<ServerRequestCancelledEvent<'_>, Status> {
        let mut out = MaybeUninit::<ffi::coquic_http3_server_request_cancelled_event_t>::uninit();
        unsafe {
            Status::into_result(ffi::coquic_http3_server_update_request_cancelled_at(
                self.ptr.as_ptr(),
                index,
                out.as_mut_ptr(),
            ))?;
            Ok(ServerRequestCancelledEvent::from_raw(out.assume_init()))
        }
    }

    pub fn has_pending_work(&self) -> bool {
        unsafe { ffi::coquic_http3_server_update_has_pending_work(self.ptr.as_ptr()) != 0 }
    }

    pub fn terminal_failure(&self) -> bool {
        unsafe { ffi::coquic_http3_server_update_terminal_failure(self.ptr.as_ptr()) != 0 }
    }

    pub fn handled_local_error(&self) -> bool {
        unsafe { ffi::coquic_http3_server_update_handled_local_error(self.ptr.as_ptr()) != 0 }
    }
}

impl Drop for ServerUpdate {
    fn drop(&mut self) {
        unsafe {
            ffi::coquic_http3_server_update_destroy(self.ptr.as_ptr());
        }
    }
}

unsafe fn connection_input_from_raw<'a>(
    raw: ffi::coquic_connection_input_t,
) -> Result<ConnectionInput<'a>, Status> {
    Ok(match raw.kind {
        ffi::COQUIC_CONNECTION_INPUT_SEND_STREAM => {
            let input = unsafe { raw.as_.send_stream };
            ConnectionInput::SendStream(crate::SendStreamData {
                stream_id: input.stream_id,
                bytes: unsafe { input_bytes(input.bytes) },
                fin: input.fin != 0,
                priority: input.priority,
            })
        }
        ffi::COQUIC_CONNECTION_INPUT_SEND_DATAGRAM => {
            let input = unsafe { raw.as_.send_datagram };
            ConnectionInput::SendDatagram(crate::SendDatagramData {
                bytes: unsafe { input_bytes(input.bytes) },
                priority: input.priority,
            })
        }
        ffi::COQUIC_CONNECTION_INPUT_RESET_STREAM => {
            let input = unsafe { raw.as_.reset_stream };
            ConnectionInput::ResetStream(crate::ResetStream {
                stream_id: input.stream_id,
                application_error_code: input.application_error_code,
            })
        }
        ffi::COQUIC_CONNECTION_INPUT_STOP_SENDING => {
            let input = unsafe { raw.as_.stop_sending };
            ConnectionInput::StopSending(crate::StopSending {
                stream_id: input.stream_id,
                application_error_code: input.application_error_code,
            })
        }
        ffi::COQUIC_CONNECTION_INPUT_CLOSE => {
            let input = unsafe { raw.as_.close };
            ConnectionInput::Close(crate::CloseConnection {
                application_error_code: input.application_error_code,
                reason_phrase: unsafe {
                    input_bytes(ffi::coquic_bytes_t {
                        data: input.reason_phrase.cast::<u8>(),
                        length: input.reason_phrase_length,
                    })
                },
            })
        }
        ffi::COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE => ConnectionInput::RequestKeyUpdate,
        ffi::COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION => {
            let input = unsafe { raw.as_.request_migration };
            ConnectionInput::RequestMigration(crate::RequestConnectionMigration {
                route_handle: input.route_handle,
                reason: match input.reason {
                    ffi::COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS => {
                        crate::MigrationReason::PreferredAddress
                    }
                    _ => crate::MigrationReason::Active,
                },
                address_validation_identity: unsafe {
                    input_bytes(input.address_validation_identity)
                },
            })
        }
        _ => return Err(Status::InvalidArgument),
    })
}

unsafe fn input_bytes<'a>(value: ffi::coquic_bytes_t) -> &'a [u8] {
    if value.data.is_null() || value.length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(value.data, value.length) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_http3_client_server() {
        let client = Client::new(&ClientConfig::default()).unwrap();
        assert!(!client.has_failed());

        let server = Server::new(&ServerConfig::default()).unwrap();
        assert!(!server.has_failed());
    }

    #[test]
    fn submit_request_without_connected_quic_queues_request() {
        let mut client = Client::new(&ClientConfig::default()).unwrap();
        let request = Request::new(RequestHead::get("example.com", "/"));
        assert_eq!(client.submit_request(&request).unwrap(), 0);
    }
}
