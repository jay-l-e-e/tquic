use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mio::net::UdpSocket;
use serde_json::{Value, json};
use url::Url;

use crate::PacketSendHandler;
use crate::h3::connection::Http3Connection;
use crate::h3::{Header, Http3Config, Http3Error, Http3Event, NameValue};
use crate::{CertCompressionAlgorithm, CongestionControlAlgorithm};
use crate::{Config, Endpoint, MultipathAlgorithm};
use crate::{Connection, PacketInfo, TlsConfig, TransportHandler};

type AnyError<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
pub struct ClientProtocolOptions {
    pub enable_early_data: bool,
    pub certificate_compression: Vec<CertCompressionAlgorithm>,
    pub disable_stateless_reset: bool,
    pub congestion_control: CongestionControlAlgorithm,
    pub max_concurrent_conns: Option<u32>,
    pub max_concurrent_requests: Option<u64>,
    pub alpn: Option<Vec<String>>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_congestion_window: Option<u64>,
    pub min_congestion_window: Option<u64>,
    pub enable_multipath: Option<bool>,
    pub multipath_algorithm: MultipathAlgorithm,
    pub active_connection_id_limit: Option<u64>,
    pub recv_udp_payload_size: Option<u16>,
    pub send_udp_payload_size: Option<usize>,
    pub handshake_timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub initial_rtt: Option<u64>,
    pub pto_linear_factor: Option<u64>,
    pub max_pto: Option<u64>,
    pub cid_len: Option<usize>,
    pub send_batch_size: Option<usize>,
    pub disable_encryption: Option<bool>,
}

impl Default for ClientProtocolOptions {
    fn default() -> Self {
        Self {
            enable_early_data: true,
            certificate_compression: vec![CertCompressionAlgorithm::Brotli],
            disable_stateless_reset: false,
            congestion_control: CongestionControlAlgorithm::Bbr,
            max_concurrent_conns: Some(1),
            max_concurrent_requests: Some(100),
            alpn: Some(vec!["h3".to_string()]),
            initial_max_streams_bidi: None,
            initial_max_streams_uni: None,
            initial_max_data: None,
            initial_max_stream_data_bidi_local: None,
            initial_max_stream_data_bidi_remote: None,
            initial_max_stream_data_uni: None,
            initial_congestion_window: Some(32),
            min_congestion_window: Some(4),
            enable_multipath: None,
            multipath_algorithm: MultipathAlgorithm::MinRtt,
            active_connection_id_limit: Some(2),
            recv_udp_payload_size: Some(1472),
            send_udp_payload_size: Some(1250),
            handshake_timeout: Some(10000),
            idle_timeout: Some(30000),
            initial_rtt: Some(333),
            pto_linear_factor: Some(10),
            max_pto: Some(10000),
            cid_len: Some(8),
            send_batch_size: Some(1),
            disable_encryption: None,
        }
    }
}

#[derive(Clone)]
pub struct RequestOptions<K: AsRef<str> = String, V: AsRef<str> = String> {
    pub method: HttpMethod,
    pub headers: Option<Vec<(K, V)>>,
    pub body: Option<Vec<u8>>,
}

impl<K: AsRef<str>, V: AsRef<str>> Default for RequestOptions<K, V> {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            headers: None,
            body: None,
        }
    }
}

impl RequestOptions<String, String> {
    pub fn new(method: HttpMethod) -> Self {
        Self {
            method,
            headers: None,
            body: None,
        }
    }

    pub fn with_headers<N: AsRef<str>, V: AsRef<str>>(mut self, headers: Vec<(N, V)>) -> Self {
        self.headers = Some(
            headers
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
                .collect(),
        );
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: Value,
    pub body: Vec<u8>,
}

impl Response {
    pub fn body_text(&self) -> String {
        let content_encoding = match &self.headers {
            Value::Object(map) => {
                if let Some(v) = map.get("content-encoding") {
                    match v {
                        Value::String(s) => Some(s.to_ascii_lowercase()),

                        Value::Array(list) => list.iter().find_map(|item| match item {
                            Value::String(s) => Some(s.to_ascii_lowercase()),

                            _ => None,
                        }),

                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(encoding) = content_encoding.as_deref() {
            if encoding == "gzip" {
                let mut decoder = flate2::read::GzDecoder::new(&self.body[..]);
                let mut output_string = String::new();

                if std::io::Read::read_to_string(&mut decoder, &mut output_string).is_ok() {
                    return output_string;
                }
            }

            if encoding == "deflate" {
                let mut decoder = flate2::read::DeflateDecoder::new(&self.body[..]);
                let mut output_string = String::new();

                if std::io::Read::read_to_string(&mut decoder, &mut output_string).is_ok() {
                    return output_string;
                }
            }

            if encoding == "br" {
                let mut decoder = brotli::Decompressor::new(&self.body[..], 4096);
                let mut output_bytes = Vec::new();

                if std::io::copy(&mut decoder, &mut output_bytes).is_ok()
                    && let Ok(decoded_string) = String::from_utf8(output_bytes)
                {
                    return decoded_string;
                }
            }

            if encoding == "zstd"
                && let Ok(mut decoder) = zstd::Decoder::new(&self.body[..])
            {
                let mut output_string = String::new();

                if std::io::Read::read_to_string(&mut decoder, &mut output_string).is_ok() {
                    return output_string;
                }
            }
        }

        String::from_utf8(self.body.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&self.body).into_owned())
    }
}

#[derive(Clone)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Trace,
    Patch,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Patch => "PATCH",
        }
    }
}

struct InternalState {
    request_plan: Option<(Url, RequestOptions<String, String>)>,
    response_headers: Vec<Header>,
    response_body: Vec<u8>,
    response_status: Option<u16>,
    finished: bool,
    connection_ready: bool,
    active_stream_id: Option<u64>,
    http3: Option<Http3Connection>,
    error: Option<String>,
    session_cache: Option<Vec<u8>>,
    current_connection_index: Option<u64>,
}

impl InternalState {
    fn new() -> Self {
        Self {
            request_plan: None,
            response_headers: vec![],
            response_body: vec![],
            response_status: None,
            finished: false,
            connection_ready: false,
            active_stream_id: None,
            http3: None,
            error: None,
            session_cache: None,
            current_connection_index: None,
        }
    }
}

pub struct Client {
    endpoint: Endpoint,
    socket_ipv4: Option<Arc<UdpSocket>>,
    socket_ipv6: Option<Arc<UdpSocket>>,
    state: Rc<RefCell<InternalState>>,
    receive_buffer: Vec<u8>,
}

impl Client {
    pub fn new(protocol_options: Option<ClientProtocolOptions>) -> AnyError<Self> {
        let protocol_options = protocol_options.unwrap_or_default();

        let mut config = Config::new()?;

        config.set_omit_client_initial_scid(true);
        config.enable_stateless_reset(!protocol_options.disable_stateless_reset);

        if let Some(value) = protocol_options.handshake_timeout {
            config.set_max_handshake_timeout(value);
        }

        if let Some(value) = protocol_options.idle_timeout {
            config.set_max_idle_timeout(value);
        }

        if let Some(value) = protocol_options.initial_rtt {
            config.set_initial_rtt(value);
        }

        if let Some(value) = protocol_options.pto_linear_factor {
            config.set_pto_linear_factor(value);
        }

        if let Some(value) = protocol_options.max_pto {
            config.set_max_pto(value);
        }

        if let Some(value) = protocol_options.cid_len {
            config.set_cid_len(value);
        }

        if let Some(value) = protocol_options.send_batch_size {
            config.set_send_batch_size(value);
        }

        if let Some(value) = protocol_options.recv_udp_payload_size {
            config.set_recv_udp_payload_size(value);
        }

        if let Some(value) = protocol_options.send_udp_payload_size {
            config.set_send_udp_payload_size(value);
        }

        if let Some(value) = protocol_options.max_concurrent_conns {
            config.set_max_concurrent_conns(value);
        }

        if let Some(value) = protocol_options.max_concurrent_requests {
            config.set_initial_max_streams_bidi(value);
        }

        if let Some(value) = protocol_options.initial_max_streams_bidi {
            config.set_initial_max_streams_bidi(value);
        }

        if let Some(value) = protocol_options.initial_max_streams_uni {
            config.set_initial_max_streams_uni(value);
        }

        if let Some(value) = protocol_options.initial_max_data {
            config.set_initial_max_data(value);
        }

        if let Some(value) = protocol_options.initial_max_stream_data_bidi_local {
            config.set_initial_max_stream_data_bidi_local(value);
        }

        if let Some(value) = protocol_options.initial_max_stream_data_bidi_remote {
            config.set_initial_max_stream_data_bidi_remote(value);
        }

        if let Some(value) = protocol_options.initial_max_stream_data_uni {
            config.set_initial_max_stream_data_uni(value);
        }

        config.set_congestion_control_algorithm(protocol_options.congestion_control);

        if let Some(value) = protocol_options.initial_congestion_window {
            config.set_initial_congestion_window(value);
        }

        if let Some(value) = protocol_options.min_congestion_window {
            config.set_min_congestion_window(value);
        }

        if let Some(value) = protocol_options.enable_multipath {
            config.enable_multipath(value);
        }

        config.set_multipath_algorithm(protocol_options.multipath_algorithm);

        if let Some(value) = protocol_options.active_connection_id_limit {
            config.set_active_connection_id_limit(value);
        }

        if let Some(value) = protocol_options.disable_encryption {
            config.enable_encryption(!value);
        }

        let alpn_list = protocol_options
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["h3".to_string()]);
        let mut tls = TlsConfig::new_client_config(
            alpn_list.into_iter().map(|s| s.into_bytes()).collect(),
            protocol_options.enable_early_data,
        )?;

        if !protocol_options.certificate_compression.is_empty() {
            tls.enable_certificate_compression(protocol_options.certificate_compression.clone())?;
        }

        config.set_tls_config(tls);

        let local_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let local_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let socket_ipv4 = bind_udp(local_v4).ok().map(Arc::new);
        let socket_ipv6 = bind_udp(local_v6).ok().map(Arc::new);
        let state = Rc::new(RefCell::new(InternalState::new()));
        let handler = ClientHandler::new(state.clone());
        let sender = std::rc::Rc::new(UdpSender {
            socket_ipv4: socket_ipv4.clone(),
            socket_ipv6: socket_ipv6.clone(),
        });
        let endpoint = Endpoint::new(Box::new(config), Box::new(handler), sender);

        Ok(Self {
            endpoint,
            socket_ipv4,
            socket_ipv6,
            state,
            receive_buffer: vec![0u8; 65536],
        })
    }

    pub async fn request<N, V>(
        &mut self,
        uri: &Url,
        request: RequestOptions<N, V>,
    ) -> AnyError<Response>
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let owned_headers = request.headers.map(|list| {
            list.into_iter()
                .map(|(name, val)| (name.as_ref().to_string(), val.as_ref().to_string()))
                .collect()
        });

        let owned_req = RequestOptions {
            method: request.method,
            headers: owned_headers,
            body: request.body,
        };

        let should_reconnect = {
            let mut state = self.state.borrow_mut();

            state.response_headers.clear();
            state.response_body.clear();
            state.response_status = None;
            state.error = None;
            state.finished = false;

            let needs_new_connection =
                state.current_connection_index.is_none() || !state.connection_ready;

            if needs_new_connection {
                state.http3 = None;
                state.connection_ready = false;
            }

            state.active_stream_id = None;
            state.request_plan = Some((uri.clone(), owned_req));

            needs_new_connection
        };

        if should_reconnect {
            self.connect()?;
        }

        self.run().await?;

        if let Some(err_message) = self.state.borrow().error.clone() {
            return Err(err_message.into());
        }

        Ok(self.build_response())
    }

    fn connect(&mut self) -> AnyError<()> {
        let (uri, _) = self
            .state
            .borrow_mut()
            .request_plan
            .clone()
            .ok_or_else(|| "no request".to_string())?;
        let remote = resolve_remote(&uri)?;
        let server_name_owned = uri.domain().map(|s| s.to_string());
        let server_name = server_name_owned.as_deref();

        let local_address = if remote.is_ipv4() {
            let socket = self
                .socket_ipv4
                .as_ref()
                .ok_or_else(|| "no ipv4 socket".to_string())?;
            socket.local_addr()?
        } else {
            let socket = self
                .socket_ipv6
                .as_ref()
                .ok_or_else(|| "no ipv6 socket".to_string())?;
            socket.local_addr()?
        };

        let session_bytes = self.state.borrow().session_cache.clone();

        let connection_index = self.endpoint.connect(
            local_address,
            remote,
            server_name,
            session_bytes.as_deref(),
            None,
            None,
        )?;

        self.state.borrow_mut().current_connection_index = Some(connection_index);
        self.state.borrow_mut().connection_ready = false;

        Ok(())
    }

    fn ensure_request_stream(&mut self) -> AnyError<()> {
        let (connection_idx, uri, request) = {
            let mut state = self.state.borrow_mut();

            if !state.connection_ready || state.active_stream_id.is_some() {
                return Ok(());
            }

            let Some(plan) = state.request_plan.take() else {
                return Ok(());
            };

            let Some(idx) = state.current_connection_index else {
                state.request_plan = Some(plan);
                return Ok(());
            };

            (idx, plan.0, plan.1)
        };

        self.start_request_on_connection(connection_idx, uri, request)
    }

    fn start_request_on_connection(
        &mut self,
        connection_idx: u64,
        uri: Url,
        request: RequestOptions<String, String>,
    ) -> AnyError<()> {
        let state_handle = self.state.clone();
        self.endpoint
            .with_connection_mut(connection_idx, |connection| {
                {
                    let mut state_mut = state_handle.borrow_mut();
                    if state_mut.http3.is_none() {
                        if let Ok(h3_config) = Http3Config::new() {
                            state_mut.http3 =
                                Http3Connection::new_with_quic_conn(connection, &h3_config).ok();
                        }
                    }
                }

                let mut state_mut = state_handle.borrow_mut();

                let Some(http3) = state_mut.http3.as_mut() else {
                    state_mut.error = Some("failed to initialize http3".to_string());
                    state_mut.finished = true;

                    return;
                };

                let Ok(stream_id) = http3.stream_new(connection) else {
                    state_mut.error = Some("failed to open HTTP/3 stream".to_string());
                    state_mut.finished = true;

                    return;
                };

                let headers = build_headers(&uri, &request);
                let has_body = request
                    .body
                    .as_ref()
                    .map(|body_bytes| !body_bytes.is_empty())
                    .unwrap_or(false);

                if let Err(err) = http3.send_headers(connection, stream_id, &headers, !has_body) {
                    state_mut.error = Some(format!("failed to send headers: {err:?}"));
                    state_mut.finished = true;

                    return;
                }

                if let Some(body_bytes) = request.body {
                    if let Err(err) =
                        http3.send_body(connection, stream_id, Bytes::from(body_bytes), true)
                    {
                        state_mut.error = Some(format!("failed to send body: {err:?}"));
                        state_mut.finished = true;

                        return;
                    }
                }

                state_mut.active_stream_id = Some(stream_id);
            })?;

        Ok(())
    }

    async fn run(&mut self) -> AnyError<()> {
        let start = Instant::now();
        loop {
            self.ensure_request_stream()?;
            self.endpoint.process_connections()?;
            self.ensure_request_stream()?;

            if self.state.borrow().finished {
                break;
            }

            self.read_socket()?;
            self.endpoint.process_connections()?;
            self.ensure_request_stream()?;

            if self.state.borrow().finished {
                break;
            }

            if let Some(wait) = self.endpoint.timeout() {
                let max_sleep_duration = Duration::from_millis(5);

                let sleep_duration = if wait > max_sleep_duration {
                    max_sleep_duration
                } else {
                    wait
                };

                if !sleep_duration.is_zero() {
                    std::thread::sleep(sleep_duration);
                }
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }

            self.endpoint.on_timeout(Instant::now());

            self.ensure_request_stream()?;
            if self.state.borrow().finished {
                break;
            }

            if Instant::now().duration_since(start).as_secs() > 60 {
                let mut state_mut = self.state.borrow_mut();

                if state_mut.error.is_none() {
                    state_mut.error = Some("request timeout".to_string());
                }

                state_mut.finished = true;

                break;
            }
        }
        Ok(())
    }

    fn read_socket(&mut self) -> AnyError<()> {
        if let Some(socket) = &self.socket_ipv4 {
            loop {
                match socket.recv_from(&mut self.receive_buffer) {
                    Ok((read_length, remote_address)) => {
                        let packet_info = PacketInfo {
                            src: remote_address,
                            dst: socket.local_addr()?,
                            time: Instant::now(),
                        };

                        self.endpoint
                            .recv(&mut self.receive_buffer[..read_length], &packet_info)?;
                    }

                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,

                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        if let Some(socket) = &self.socket_ipv6 {
            loop {
                match socket.recv_from(&mut self.receive_buffer) {
                    Ok((read_length, remote_address)) => {
                        let packet_info = PacketInfo {
                            src: remote_address,
                            dst: socket.local_addr()?,
                            time: Instant::now(),
                        };
                        self.endpoint
                            .recv(&mut self.receive_buffer[..read_length], &packet_info)?;
                    }

                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,

                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        Ok(())
    }

    fn build_response(&self) -> Response {
        let snapshot = self.state.borrow();
        let status = snapshot.response_status.unwrap_or(0);
        let status_text = status_text(status).to_string();
        let mut header_map: BTreeMap<String, Value> = BTreeMap::new();

        for header in &snapshot.response_headers {
            let name = String::from_utf8_lossy(header.name()).into_owned();
            let value = String::from_utf8_lossy(header.value()).into_owned();

            match header_map.get_mut(&name) {
                Some(existing) => match existing {
                    Value::String(prev) => {
                        let arr = vec![Value::String(prev.clone()), Value::String(value)];

                        *existing = Value::Array(arr);
                    }

                    Value::Array(list) => {
                        list.push(Value::String(value));
                    }

                    _ => {
                        header_map.insert(name, Value::String(value));
                    }
                },
                None => {
                    header_map.insert(name, Value::String(value));
                }
            }
        }

        let headers = Value::Object(header_map.into_iter().collect());

        Response {
            status,
            status_text,
            headers,
            body: snapshot.response_body.clone(),
        }
    }
}

struct ClientHandler {
    state: Rc<RefCell<InternalState>>,
}

impl ClientHandler {
    fn new(state: Rc<RefCell<InternalState>>) -> Self {
        Self { state }
    }

    fn ensure_http3_initialized(&self, connection: &mut Connection) {
        let need_initialize = {
            let state_ref = self.state.borrow();
            state_ref.http3.is_none()
        };

        if !need_initialize {
            return;
        }

        if let Ok(h3_config) = Http3Config::new() {
            self.state.borrow_mut().http3 =
                Http3Connection::new_with_quic_conn(connection, &h3_config).ok();
        }
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, connection: &mut Connection) {
        if let Some(current_idx) = self.state.borrow().current_connection_index {
            if connection.index() != Some(current_idx) {
                return;
            }
        }

        if !connection.is_in_early_data() {
            return;
        }

        self.ensure_http3_initialized(connection);
        self.state.borrow_mut().connection_ready = true;
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        if let Some(current_idx) = self.state.borrow().current_connection_index {
            if conn.index() != Some(current_idx) {
                return;
            }
        }

        let mut state = self.state.borrow_mut();
        state.connection_ready = false;
        state.active_stream_id = None;
        state.current_connection_index = None;

        if state.session_cache.is_none() {
            if let Some(buf) = conn.session() {
                state.session_cache = Some(buf.to_vec());
            }
        }

        if let Some(local_err) = conn.local_error() {
            if !local_err.is_app {
                state.error = Some(format!(
                    "local error: code={}, reason={}",
                    local_err.error_code,
                    String::from_utf8_lossy(&local_err.reason)
                ));
            }
        } else if let Some(peer_err) = conn.peer_error() {
            state.error = Some(format!(
                "peer error: code={}, reason={}",
                peer_err.error_code,
                String::from_utf8_lossy(&peer_err.reason)
            ));
        } else if conn.is_handshake_timeout() {
            state.error = Some("handshake timeout".to_string());
        } else if conn.is_idle_timeout() {
            state.error = Some("idle timeout".to_string());
        } else if conn.is_reset() {
            state.error = Some("stateless reset".to_string());
        } else if state.error.is_none() {
            state.error = Some("connection closed".to_string());
        }

        state.finished = true;
    }

    fn on_stream_created(&mut self, _: &mut Connection, _stream_id: u64) {}

    fn on_stream_writable(&mut self, _: &mut Connection, _stream_id: u64) {}

    fn on_stream_closed(&mut self, _: &mut Connection, _stream_id: u64) {}

    fn on_new_token(&mut self, _: &mut Connection, _token: Vec<u8>) {}

    fn on_conn_established(&mut self, connection: &mut Connection) {
        if let Some(current_idx) = self.state.borrow().current_connection_index {
            if connection.index() != Some(current_idx) {
                return;
            }
        }

        self.ensure_http3_initialized(connection);
        self.state.borrow_mut().connection_ready = true;
    }

    fn on_stream_readable(&mut self, connection: &mut Connection, _stream_id: u64) {
        if let Some(current_idx) = self.state.borrow().current_connection_index {
            if connection.index() != Some(current_idx) {
                return;
            }
        }

        let mut buffer_bytes = vec![0u8; 65536];

        loop {
            let event = {
                let mut state_mut = self.state.borrow_mut();

                match state_mut.http3.as_mut() {
                    Some(http3) => http3.poll(connection),
                    None => return,
                }
            };

            match event {
                Ok((_, Http3Event::Headers { headers, .. })) => {
                    let mut state = self.state.borrow_mut();
                    for header in headers {
                        if header.name().eq_ignore_ascii_case(b":status")
                            && let Ok(status_text_str) = std::str::from_utf8(header.value())
                            && let Ok(status_code) = status_text_str.parse::<u16>()
                        {
                            state.response_status = Some(status_code);
                        }

                        state.response_headers.push(header);
                    }
                }

                Ok((stream_id, Http3Event::Data)) => loop {
                    let read_result = {
                        let mut state_mut = self.state.borrow_mut();

                        if let Some(http3) = state_mut.http3.as_mut() {
                            match http3.recv_body(connection, stream_id, &mut buffer_bytes) {
                                Ok(len) => Some(Ok(len)),
                                Err(Http3Error::Done) => Some(Err(Http3Error::Done)),
                                Err(e) => Some(Err(e)),
                            }
                        } else {
                            None
                        }
                    };

                    match read_result {
                        Some(Ok(read_length)) => {
                            if read_length == 0 {
                                break;
                            }

                            let mut state_mut = self.state.borrow_mut();
                            state_mut
                                .response_body
                                .extend_from_slice(&buffer_bytes[..read_length]);

                            continue;
                        }

                        Some(Err(Http3Error::Done)) | None => break,

                        Some(Err(_)) => {
                            break;
                        }
                    }
                },

                Ok((stream_id, Http3Event::Finished)) => {
                    if let Some(buf) = connection.session() {
                        self.state.borrow_mut().session_cache = Some(buf.to_vec());
                    }

                    {
                        let mut state_mut = self.state.borrow_mut();
                        if state_mut.active_stream_id == Some(stream_id) {
                            state_mut.active_stream_id = None;
                        }
                        state_mut.finished = true;
                    }

                    return;
                }

                Ok((stream_id, Http3Event::Reset(_))) => {
                    {
                        let mut state_mut = self.state.borrow_mut();
                        if state_mut.active_stream_id == Some(stream_id) {
                            state_mut.active_stream_id = None;
                        }
                        state_mut.finished = true;
                    }
                    let _ = connection.close(true, 0x00, b"reset");

                    return;
                }

                Ok((stream_id, Http3Event::GoAway)) => {
                    {
                        let mut state_mut = self.state.borrow_mut();
                        if state_mut.active_stream_id == Some(stream_id) {
                            state_mut.active_stream_id = None;
                        }
                        state_mut.finished = true;
                    }
                    let _ = connection.close(true, 0x00, b"goaway");

                    return;
                }

                Ok((_, Http3Event::PriorityUpdate)) => {}

                Err(Http3Error::Done) => return,

                Err(_) => {
                    {
                        let mut state_mut = self.state.borrow_mut();
                        state_mut.active_stream_id = None;
                        state_mut.finished = true;
                    }
                    let _ = connection.close(true, 0x00, b"err");

                    return;
                }
            }
        }
    }
}

fn resolve_remote(target: &Url) -> AnyError<SocketAddr> {
    let port = target.port().unwrap_or(443);
    let list = target.socket_addrs(|| Some(port))?;

    let mut addr = *list.first().ok_or_else(|| "resolve".to_string())?;

    if addr.is_ipv4() && addr.ip() == Ipv4Addr::UNSPECIFIED {
        addr.set_ip(Ipv4Addr::LOCALHOST.into());
    }

    if addr.is_ipv6() && addr.ip() == Ipv6Addr::UNSPECIFIED {
        addr.set_ip(Ipv6Addr::LOCALHOST.into());
    }

    Ok(addr)
}

fn build_headers<N, V>(uri: &Url, req: &RequestOptions<N, V>) -> Vec<Header>
where
    N: AsRef<str>,
    V: AsRef<str>,
{
    let host_string = match uri.host_str() {
        Some(host_value) => host_value.to_string(),
        None => String::new(),
    };

    let authority = if let Some(port_value) = uri.port() {
        format!("{}:{}", host_string, port_value)
    } else {
        host_string
    };

    let mut header_list = vec![
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":method", req.method.as_str().as_bytes()),
        Header::new(b":path", uri[url::Position::BeforePath..].as_bytes()),
        Header::new(b":scheme", uri.scheme().as_bytes()),
    ];

    if let Some(custom_headers) = &req.headers {
        for (header_name, header_value) in custom_headers {
            header_list.push(Header::new(
                header_name.as_ref().as_bytes(),
                header_value.as_ref().as_bytes(),
            ));
        }
    }

    if let Some(payload_bytes) = &req.body {
        header_list.push(Header::new(
            b"content-length",
            payload_bytes.len().to_string().as_bytes(),
        ));
    }

    header_list
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

struct UdpSender {
    socket_ipv4: Option<Arc<UdpSocket>>,
    socket_ipv6: Option<Arc<UdpSocket>>,
}

impl PacketSendHandler for UdpSender {
    fn on_packets_send(&self, packets: &[(Vec<u8>, PacketInfo)]) -> crate::Result<usize> {
        let mut sent_count = 0;
        for (buffer, packet_info) in packets {
            let result = if packet_info.dst.is_ipv4() {
                if let Some(socket) = &self.socket_ipv4 {
                    socket.send_to(buffer, packet_info.dst)
                } else {
                    Err(std::io::Error::other("no ipv4 socket"))
                }
            } else if let Some(socket) = &self.socket_ipv6 {
                socket.send_to(buffer, packet_info.dst)
            } else {
                Err(std::io::Error::other("no ipv6 socket"))
            };

            match result {
                Ok(_) => sent_count += 1,

                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,

                Err(_) => break,
            }
        }

        Ok(sent_count)
    }
}

fn bind_udp(local: SocketAddr) -> AnyError<UdpSocket> {
    let std_socket = std::net::UdpSocket::bind(local)?;

    std_socket.set_nonblocking(true)?;

    Ok(UdpSocket::from_std(std_socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_google_request() {
        futures::executor::block_on(async {
            let mut client = Client::new(None).unwrap();
            let request_options: RequestOptions<String, String> = RequestOptions {
                method: HttpMethod::Get,
                headers: None,
                body: None,
            };
            let response = client
                .request(
                    &Url::parse("https://www.google.com/").unwrap(),
                    request_options,
                )
                .await
                .unwrap();

            assert!(response.status == 200);
        });
    }

    #[test]
    fn test_google_request_with_headers() {
        futures::executor::block_on(async {
            let mut client = Client::new(None).unwrap();
            let request_options = RequestOptions {
                method: HttpMethod::Get,
                headers: Some(vec![
                    ("accept", "*/*"),
                    ("accept-encoding", "gzip, deflate, br, zstd"),
                    ("accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"),
                    ("cache-control", "no-cache"),
                    ("pragma", "no-cache"),
                    ("priority", "u=0, i"),
                    (
                        "sec-ch-ua",
                        "\"Google Chrome\";v=\"141\", \"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"141\"",
                    ),
                    ("sec-ch-ua-arch", "\"x86\""),
                    ("sec-ch-ua-itness", "\"64\""),
                    ("sec-ch-ua-full-version", "\"141.0.7390.108\""),
                    (
                        "sec-ch-ua-full-version-list",
                        "Google Chrome;v=\"141.0.7390.108\", Not?A_Brand;v=\"8.0.0.0\", Chromium;v=\"141.0.7390.108\"",
                    ),
                    ("sec-ch-ua-moile", "?0"),
                    ("sec-ch-ua-model", "\"\""),
                    ("sec-ch-ua-platform", "\"Windows\""),
                    ("sec-ch-ua-platform-version", "\"19.0.0\""),
                    ("sec-fetch-dest", "document"),
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-site", "same-origin"),
                    ("sec-fetch-user", "?1"),
                    ("upgrade-insecure-requests", "1"),
                    (
                        "user-agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                    ),
                ]),
                body: None,
            };

            let response = client
                .request(
                    &Url::parse("https://www.google.com/").unwrap(),
                    request_options,
                )
                .await
                .unwrap();

            assert!(response.status == 200);
        });
    }

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Head.as_str(), "HEAD");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Options.as_str(), "OPTIONS");
        assert_eq!(HttpMethod::Trace.as_str(), "TRACE");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
    }

    #[test]
    fn test_build_headers_basic_get() {
        let uri = Url::parse("https://example.com:8443/path?q=1").unwrap();
        let request_options = RequestOptions::new(HttpMethod::Get);
        let headers = build_headers(&uri, &request_options);

        let mut map = std::collections::HashMap::new();
        for header in headers {
            map.insert(
                String::from_utf8_lossy(header.name()).into_owned(),
                String::from_utf8_lossy(header.value()).into_owned(),
            );
        }

        assert_eq!(map.get(":method").map(|s| s.as_str()), Some("GET"));
        assert_eq!(map.get(":scheme").map(|s| s.as_str()), Some("https"));
        assert_eq!(
            map.get(":authority").map(|s| s.as_str()),
            Some("example.com:8443")
        );
        assert_eq!(map.get(":path").map(|s| s.as_str()), Some("/path?q=1"));
        assert!(map.get("content-length").is_none());
    }

    #[test]
    fn test_build_headers_with_body_and_custom() {
        let uri = Url::parse("https://example.com/").unwrap();
        let body = b"hello".to_vec();
        let custom_headers = vec![("x-test", "1")];
        let request_options = RequestOptions::new(HttpMethod::Post)
            .with_headers(custom_headers)
            .with_body(body.clone());
        let headers = build_headers(&uri, &request_options);

        let mut map = std::collections::HashMap::new();

        for header in headers {
            map.insert(
                String::from_utf8_lossy(header.name()).into_owned(),
                String::from_utf8_lossy(header.value()).into_owned(),
            );
        }

        assert_eq!(map.get(":method").map(|s| s.as_str()), Some("POST"));
        assert_eq!(map.get("content-length").map(|s| s.as_str()), Some("5"));
        assert_eq!(map.get("x-test").map(|s| s.as_str()), Some("1"));
    }

    #[test]
    fn test_response_body_text_plain_utf8() {
        let body = b"hello world".to_vec();
        let response = Response {
            status: 200,
            status_text: "OK".into(),
            headers: json!({"content-type": "text/plain"}),
            body,
        };

        assert_eq!(response.body_text(), "hello world");
    }

    #[test]
    fn test_response_body_text_gzip() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());

        encoder.write_all(b"hello gzip").unwrap();

        let body = encoder.finish().unwrap();
        let response = Response {
            status: 200,
            status_text: "OK".into(),
            headers: json!({"content-encoding": "gzip"}),
            body,
        };

        assert_eq!(response.body_text(), "hello gzip");
    }

    #[test]
    fn test_response_body_text_deflate() {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());

        encoder.write_all(b"hello deflate").unwrap();

        let body = encoder.finish().unwrap();
        let response = Response {
            status: 200,
            status_text: "OK".into(),
            headers: json!({"content-encoding": "deflate"}),
            body,
        };

        assert_eq!(response.body_text(), "hello deflate");
    }

    #[test]
    fn test_response_body_text_brotli() {
        let mut compressed = Vec::new();

        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(b"hello br").unwrap();
        }

        let response = Response {
            status: 200,
            status_text: "OK".into(),
            headers: json!({"content-encoding": "br"}),
            body: compressed,
        };

        assert_eq!(response.body_text(), "hello br");
    }

    #[test]
    fn test_response_body_text_zstd() {
        let body = zstd::stream::encode_all(&b"hello zstd"[..], 0).unwrap();
        let response = Response {
            status: 200,
            status_text: "OK".into(),
            headers: json!({"content-encoding": "zstd"}),
            body,
        };

        assert_eq!(response.body_text(), "hello zstd");
    }

    #[test]
    fn test_resolve_remote_unspecified_ipv4() {
        let url = Url::parse("https://0.0.0.0/").unwrap();
        let address = resolve_remote(&url).unwrap();

        assert!(address.is_ipv4());
        assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(address.port(), 443);
    }

    #[test]
    fn test_resolve_remote_unspecified_ipv6() {
        let url = Url::parse("https://[::]/").unwrap();
        let address = resolve_remote(&url).unwrap();

        assert!(address.is_ipv6());
        assert_eq!(address.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(address.port(), 443);
    }
}
