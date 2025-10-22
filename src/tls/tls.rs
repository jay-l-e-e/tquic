// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::mem;
use std::ops::Index;
use std::ops::IndexMut;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use log::debug;
use log::trace;
use strum::EnumCount;
use strum::IntoEnumIterator;
use strum_macros::EnumCount;
use strum_macros::EnumIter;

use crate::ConnectionId;
use crate::Error;
use crate::Result;
use crate::codec::Decoder;
use crate::connection::space::PacketNumSpace;
use crate::connection::timer::Timer;
use crate::connection::timer::TimerTable;
use crate::packet::PacketHeader;
use crate::packet::PacketType;

pub use boringssl::crypto::Algorithm;
pub use boringssl::crypto::Open;
pub use boringssl::crypto::Seal;
pub use boringssl::crypto::derive_initial_secrets;
pub use boringssl::tls::CertCompressionAlgorithm;
pub use boringssl::tls::SslCtx;
pub use boringssl::tls::SslEarlyDataReason;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, EnumCount)]
pub enum Level {
    Initial,
    ZeroRTT,
    Handshake,
    OneRTT,
}

impl From<Level> for usize {
    fn from(level: Level) -> Self {
        level as usize
    }
}

impl<T> Index<Level> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, level: Level) -> &Self::Output {
        self.index(usize::from(level))
    }
}

impl<T> IndexMut<Level> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, level: Level) -> &mut Self::Output {
        self.index_mut(usize::from(level))
    }
}

pub struct TlsConfig {
    /// Boringssl SSL context.
    tls_ctx: boringssl::tls::Context,
}

impl TlsConfig {
    /// Create a new TlsConfig.
    pub fn new() -> Result<Self> {
        let mut tls_ctx = boringssl::tls::Context::new()?;
        tls_ctx.enable_keylog();

        Ok(Self { tls_ctx })
    }

    /// Create a new TlsConfig with SSL_CTX.
    /// When using raw SSL_CTX, TlsSession::session() and TlsSession::set_keylog() won't take effect.
    /// The caller is responsible for the memory of SSL_CTX when use this function.
    pub fn new_with_ssl_ctx(ssl_ctx: *mut boringssl::tls::SslCtx) -> Self {
        let tls_ctx = boringssl::tls::Context::new_with_ssl_ctx(ssl_ctx);

        Self { tls_ctx }
    }

    /// Create a new client side TlsConfig.
    pub fn new_client_config(
        application_protos: Vec<Vec<u8>>,
        enable_early_data: bool,
    ) -> Result<Self> {
        let mut tls_config = Self::new()?;
        tls_config.set_application_protos(application_protos)?;
        tls_config.set_early_data_enabled(enable_early_data);

        Ok(tls_config)
    }

    /// Create a new server side TlsConfig.
    pub fn new_server_config(
        cert_file: &str,
        key_file: &str,
        application_protos: Vec<Vec<u8>>,
        enable_early_data: bool,
    ) -> Result<Self> {
        let mut tls_config = Self::new()?;
        tls_config.set_certificate_file(cert_file)?;
        tls_config.set_private_key_file(key_file)?;
        tls_config.set_application_protos(application_protos)?;
        tls_config.set_early_data_enabled(enable_early_data);
        // TLS 1.3 sets a limit of seven days on the time between the original
        // connection and any attempt to use 0-RTT.
        tls_config.set_session_timeout(7 * 24 * 60 * 60);

        Ok(tls_config)
    }

    /// Set whether early data is allowed.
    pub fn set_early_data_enabled(&mut self, enable_early_data: bool) {
        self.tls_ctx.set_early_data_enabled(enable_early_data)
    }

    /// Set the session lifetime in seconds
    pub fn set_session_timeout(&mut self, timeout: u32) {
        self.tls_ctx.set_session_psk_dhe_timeout(timeout)
    }

    /// Set the list of supported application protocols.
    pub fn set_application_protos(&mut self, application_protos: Vec<Vec<u8>>) -> Result<()> {
        self.tls_ctx.set_alpn(application_protos)
    }

    /// Set session ticket key for server.
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.tls_ctx.set_ticket_key(key)
    }

    /// Set the certificate verification behavior.
    pub fn set_verify(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify)
    }

    /// Set the PEM-encoded certificate file
    pub fn set_certificate_file(&mut self, cert_file: &str) -> Result<()> {
        self.tls_ctx.use_certificate_chain_file(cert_file)
    }

    /// Set the PEM-encoded private key file
    pub fn set_private_key_file(&mut self, key_file: &str) -> Result<()> {
        self.tls_ctx.use_private_key_file(key_file)
    }

    /// Set CA certificates.
    pub fn set_ca_certs(&mut self, ca_path: &str) -> Result<()> {
        let path = Path::new(ca_path);
        if path.is_file() {
            self.tls_ctx.load_verify_locations_from_file(ca_path)?;
        } else {
            self.tls_ctx.load_verify_locations_from_directory(ca_path)?;
        }

        Ok(())
    }

    /// Enable certificate compression for one or more algorithms.
    /// Supported algorithms: Zlib, Brotli
    /// Returns Ok(()) on success, Err on failure.
    pub fn enable_certificate_compression(
        &mut self,
        algorithms: Vec<boringssl::tls::CertCompressionAlgorithm>,
    ) -> Result<()> {
        for algorithm in algorithms {
            self.tls_ctx.add_cert_compression_alg(algorithm)?;
        }
        Ok(())
    }

    /// Get the underlying SSL_CTX.
    pub(crate) fn ssl_ctx(&mut self) -> *mut boringssl::tls::SslCtx {
        self.tls_ctx.as_mut_ptr()
    }
}

impl TlsConfig {
    /// Create new TlsSession.
    pub(crate) fn new_session(&self, host_name: Option<&str>) -> Result<TlsSession> {
        let mut session = self.tls_ctx.new_session()?;
        debug!("new session");

        session.init()?;

        debug!("init session");

        if let Some(host_name) = host_name {
            session.set_host_name(host_name)?;
            debug!("set host name");
        }

        Ok(TlsSession {
            session,
            data: TlsSessionData {
                key_collection: [
                    Keys::default(),
                    Keys::default(),
                    Keys::default(),
                    Keys::default(),
                ],
                session: None,
                keylog: None,
                error: None,
                trace_id: "".to_string(),
                write_method: None,
                conf_selector: None,
                early_data_rejected: false,
            },
            current_key_phase: false,
            prev_key: None,
            next_key: None,
        })
    }
}

pub(crate) struct DefaultTlsConfigSelector {
    pub tls_config: Arc<TlsConfig>,
}

impl TlsConfigSelector for DefaultTlsConfigSelector {
    /// Get default TLS config.
    fn get_default(&self) -> Option<Arc<TlsConfig>> {
        Some(self.tls_config.clone())
    }

    /// Find TLS config according to server name.
    fn select(&self, _server_name: &str) -> Option<Arc<TlsConfig>> {
        Some(self.tls_config.clone())
    }
}

/// Used for selecting TLS config according to SNI.
pub trait TlsConfigSelector: Send + Sync {
    /// Get default TLS config.
    fn get_default(&self) -> Option<Arc<TlsConfig>>;

    /// Find TLS config according to server name.
    fn select(&self, server_name: &str) -> Option<Arc<TlsConfig>>;
}

#[derive(Default)]
pub struct Keys {
    pub open: Option<Open>,
    pub seal: Option<Seal>,
}

pub type WriteMethod = Box<dyn FnMut(Level, &[u8]) -> Result<()>>;
type KeyLog = Box<dyn std::io::Write + Send + Sync>;

pub struct TlsSessionData {
    key_collection: [Keys; Level::COUNT],
    session: Option<Vec<u8>>,
    keylog: Option<KeyLog>,
    error: Option<TlsError>,
    trace_id: String,
    write_method: Option<WriteMethod>,
    conf_selector: Option<Arc<dyn TlsConfigSelector>>,
    early_data_rejected: bool,
}

pub(crate) struct TlsSession {
    /// Boringssl TLS session.
    session: boringssl::tls::Session,

    /// TLS session data.
    data: TlsSessionData,

    /// Current key phase.
    current_key_phase: bool,

    /// Keys for previous key phase.
    prev_key: Option<Keys>,

    /// Keys for next key phase.
    next_key: Option<Keys>,
}

impl TlsSession {
    /// Set write method.
    pub fn set_write_method(&mut self, write_method: WriteMethod) {
        self.data.write_method = Some(write_method);
    }

    /// Set transport parameters sent in the quic_transport_parameters extension.
    pub fn set_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        self.session.set_quic_transport_params(buf)
    }

    /// Set session for resumption.
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        self.session.set_session(session)
    }

    /// Set key logger.
    pub fn set_keylog(&mut self, keylog: KeyLog) {
        self.data.keylog = Some(keylog)
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.data.trace_id = trace_id.to_string();
    }

    /// Set TLS config selector.
    pub fn set_config_selector(&mut self, conf_selector: Arc<dyn TlsConfigSelector>) {
        self.data.conf_selector = Some(conf_selector);
        self.session.set_cert_cb();
    }

    /// Derive initial secrets.
    pub fn derive_initial_secrets(&mut self, cid: &ConnectionId, version: u32) -> Result<()> {
        let (open, seal) = boringssl::crypto::derive_initial_secrets(cid, version)?;
        self.data.key_collection[Level::Initial] = Keys {
            open: Some(open),
            seal: Some(seal),
        };
        Ok(())
    }

    /// Get the keys for the given encryption level.
    pub fn get_keys(&self, level: Level) -> &Keys {
        &self.data.key_collection[level]
    }

    /// Drop the keys for the given encryption level.
    pub fn drop_keys(&mut self, level: Level) {
        self.data.key_collection[level] = Keys::default();
    }

    /// Derive next keys.
    fn derive_keys(&self) -> Result<Keys> {
        let key = &self.data.key_collection[Level::OneRTT];
        if key.open.is_none() || key.seal.is_none() {
            return Err(Error::TlsFail("derive not available now".into()));
        }

        Ok(Keys {
            open: Some(key.open.as_ref().unwrap().derive_next_packet_key()?),
            seal: Some(key.seal.as_ref().unwrap().derive_next_packet_key()?),
        })
    }

    /// Select decryption key.
    pub fn select_key(
        &mut self,
        confirmed: bool,
        enable_multipath: bool,
        hdr: &PacketHeader,
        space: &PacketNumSpace,
    ) -> Result<(&Open, bool)> {
        if !confirmed
            || hdr.pkt_type != PacketType::OneRTT
            || self.current_key_phase == hdr.key_phase
            || enable_multipath
        {
            trace!("{} select current key", self.data.trace_id);
            let key = self.get_keys(hdr.pkt_type.to_level()?);
            return Ok((key.open.as_ref().ok_or(Error::InternalError)?, false));
        }

        if let Some(first_pkt_num_recv) = space.first_pkt_num_recv
            && hdr.pkt_num > first_pkt_num_recv
        {
            trace!("{} select next key", self.data.trace_id);

            if self.next_key.is_none() {
                self.next_key = Some(self.derive_keys()?);
            }
            let next_key = self.next_key.as_ref().unwrap();
            return Ok((next_key.open.as_ref().ok_or(Error::InternalError)?, true));
        }

        if let Some(prev_key) = &self.prev_key {
            trace!("{} select previous key", self.data.trace_id);

            return Ok((prev_key.open.as_ref().ok_or(Error::InternalError)?, false));
        }

        trace!("{} previous key already discarded", self.data.trace_id);
        Err(Error::Done)
    }

    /// Update key.
    fn update_key(&mut self, space: &mut PacketNumSpace) -> Result<()> {
        if self.next_key.is_none() {
            self.next_key = Some(self.derive_keys()?);
        }

        self.current_key_phase = !self.current_key_phase;
        self.prev_key = Some(mem::replace(
            &mut self.data.key_collection[Level::OneRTT],
            self.next_key.take().unwrap(),
        ));
        space.first_pkt_num_recv = None;
        space.first_pkt_num_sent = None;

        Ok(())
    }

    /// Try to update key after receiving a packet.
    pub fn try_update_key(
        &mut self,
        timers: &mut TimerTable,
        space: &mut PacketNumSpace,
        attempt_key_update: bool,
        hdr: &PacketHeader,
        now: Instant,
        max_pto: Option<Duration>,
    ) -> Result<()> {
        if attempt_key_update {
            self.update_key(space)?;
        }

        if space.first_pkt_num_recv.is_none() && self.current_key_phase == hdr.key_phase {
            space.first_pkt_num_recv = Some(hdr.pkt_num);

            if self.prev_key.is_some()
                && let Some(duration) = max_pto
            {
                // An endpoint SHOULD retain old read keys for no more than three times the PTO after
                // having received a packet protected using the new keys. After this period, old read
                // keys and their corresponding secrets SHOULD be discarded.
                // See RFC 9001 Section 6.5.
                timers.set(Timer::KeyDiscard, now + duration * 3);
            }
        }

        Ok(())
    }

    /// If a key update is allowed to initiate.
    fn key_update_allowed(&self, enable_multipath: bool, space: &PacketNumSpace) -> Result<bool> {
        if enable_multipath {
            // TODO: support key update in multipath scenario.
            return Ok(false);
        }

        if let Some(first_pkt_num_sent) = space.first_pkt_num_sent
            && first_pkt_num_sent <= space.largest_acked_pkt
        {
            return Ok(true);
        }

        Ok(false)
    }

    /// Initiate a key update.
    pub fn initiate_key_update(
        &mut self,
        space: &mut PacketNumSpace,
        enable_multipath: bool,
    ) -> Result<()> {
        if !self.key_update_allowed(enable_multipath, space)? {
            return Err(Error::Done);
        }

        self.update_key(space)
    }

    /// Discard the previous key.
    pub fn discard_prev_key(&mut self) {
        self.prev_key = None;
    }

    /// Return the current key phase.
    pub fn current_key_phase(&self) -> bool {
        self.current_key_phase
    }

    /// Get overhead size of Seal operation
    pub fn get_overhead(&self, level: Level) -> Option<usize> {
        self.data.key_collection[level]
            .seal
            .as_ref()
            .map(|seal| seal.algor().tag_len())
    }

    /// Provide data read from QUIC at a particular encryption level and
    /// advance the current handshake.
    pub fn provide(&mut self, level: Level, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Err(Error::TlsFail("no data".to_string()));
        }

        self.session.provide_data(level, buf)?;
        self.process()
    }

    /// Process the current handshake.
    /// If no handshake is in progress, initialize a new one.
    pub fn process(&mut self) -> Result<()> {
        if self.session.is_completed() {
            return self.session.process_post_handshake(&mut self.data);
        }

        self.session.do_handshake(&mut self.data)?;
        if self.session.is_completed() {
            self.data.conf_selector = None;
        }

        Ok(())
    }

    /// Reset tls session state.
    pub fn clear(&mut self) -> Result<()> {
        self.session.clear()
    }

    /// Get tls error.
    pub fn error(&self) -> Option<&TlsError> {
        match self.data.error {
            Some(ref err) => Some(err),
            _ => None,
        }
    }

    pub fn session(&self) -> Option<&[u8]> {
        self.data.session.as_deref()
    }

    /// Return true if tls session has a pending handshake that has progressed enough
    /// to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.session.is_in_early_data()
    }

    pub fn is_completed(&self) -> bool {
        self.session.is_completed()
    }

    pub fn is_resumed(&self) -> bool {
        self.session.is_resumed()
    }

    pub fn peer_transport_params(&self) -> &[u8] {
        self.session.quic_transport_params()
    }

    pub fn write_level(&self) -> Level {
        self.session.write_level()
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        self.session.alpn_protocol()
    }

    pub fn server_name(&self) -> Option<&str> {
        self.session.server_name()
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.session.peer_cert()
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        self.session.peer_cert_chain()
    }

    pub fn cipher(&self) -> Option<boringssl::crypto::Algorithm> {
        self.session.cipher()
    }

    pub fn curve(&self) -> Option<String> {
        self.session.curve()
    }

    pub fn peer_sign_algor(&self) -> Option<String> {
        self.session.peer_sign_algor()
    }

    pub fn early_data_reason(&self) -> SslEarlyDataReason {
        self.session.early_data_reason()
    }

    pub fn early_data_reason_string(&self) -> Result<Option<&str>> {
        self.session.early_data_reason_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsError {
    /// The error code carried by the `CONNECTION_CLOSE` frame.
    pub error_code: u64,

    /// The reason carried by the `CONNECTION_CLOSE` frame.
    pub reason: Vec<u8>,
}

#[path = "boringssl/boringssl.rs"]
mod boringssl;

mod key;
