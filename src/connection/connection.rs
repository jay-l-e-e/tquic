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

//! Implementation of QUIC protocol.

#![allow(unused_variables)]

use core::ops::Range;
use std::any::Any;
use std::cell::RefCell;
use std::cmp;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time;

use bytes::Bytes;
use enumflags2::BitFlags;
use enumflags2::bitflags;
use log::*;
use strum::IntoEnumIterator;

use self::ConnectionFlags::*;
use self::cid::ConnectionIdItem;
use self::space::BufferFlags;
use self::space::BufferType;
use self::space::PacketNumSpace;
use self::space::RateSamplePacketState;
use self::space::SpaceId;
use self::stream::Stream;
use self::stream::StreamIter;
use self::timer::Timer;
use crate::Config;
use crate::ConnectionId;
use crate::ConnectionIdGenerator;
use crate::ConnectionQueues;
use crate::Event;
use crate::EventQueue;
use crate::FourTuple;
use crate::FourTupleIter;
use crate::MultipathConfig;
use crate::PacketInfo;
use crate::PathEvent;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::Shutdown;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::ConnectionError;
use crate::error::Error;
use crate::frame;
use crate::frame::Frame;
use crate::multipath_scheduler::*;
use crate::packet;
use crate::packet::PacketHeader;
use crate::packet::PacketType;
#[cfg(feature = "qlog")]
use crate::qlog;
#[cfg(feature = "qlog")]
use crate::qlog::events;
use crate::tls;
use crate::tls::Keys;
use crate::tls::Level;
use crate::tls::Open;
use crate::tls::TlsSession;
use crate::token::AddressToken;
use crate::token::ResetToken;
use crate::trans_param::TransportParams;

/// A QUIC connection.
pub struct Connection {
    /// QUIC version used for the connection.
    version: u32,

    /// Connection Identifiers.
    cids: cid::ConnectionIdMgr,

    /// Packet number spaces.
    spaces: space::PacketNumSpaceMap,

    /// The path manager.
    paths: path::PathMap,

    /// Multipath scheduler for MPQUIC
    multipath_scheduler: Option<Box<dyn MultipathScheduler>>,

    /// Config for multipath scheduler
    multipath_conf: MultipathConfig,

    /// When true (client only), omit SCID in Initial packet headers.
    omit_client_initial_scid: bool,

    /// The stream manager.
    streams: stream::StreamMap,

    /// TLS session.
    tls_session: TlsSession,

    /// The crypto streams for Initial/Handshake/1RTT level, each of which
    /// starts at an offset of 0.
    crypto_streams: Rc<RefCell<CryptoStreams>>,

    /// Raw packets that were received before decryption keys are available.
    undecryptable_packets: UndecryptablePackets,

    /// Peer transport parameters.
    peer_transport_params: TransportParams,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// Recovery and congestion control configurations.
    recovery_conf: RecoveryConfig,

    /// Error to be sent to the peer in a CONNECTION_CLOSE frame.
    local_error: Option<ConnectionError>,

    /// Error received from the peer in a CONNECTION_CLOSE frame.
    peer_error: Option<ConnectionError>,

    /// Various connection timers.
    timers: timer::TimerTable,

    /// Various connection states.
    flags: BitFlags<ConnectionFlags>,

    /// Various connection metrics.
    stats: ConnectionStats,

    /// Original destination connection ID created by the client.
    odcid: Option<ConnectionId>,

    /// Retry source connection ID from server.
    rscid: Option<ConnectionId>,

    /// For client, it is the received address token from server;
    /// For server, it is the resume address token to issue to the client.
    token: Option<Vec<u8>>,

    /// Internal Identifier of connection on the Endpoint.
    index: Option<u64>,

    /// Events to be sent to the endpoint.
    events: EventQueue,

    /// Status observed by the endpoint.
    queues: Option<Rc<RefCell<ConnectionQueues>>>,

    /// User context for the connection.
    context: Option<Box<dyn Any + Send + Sync>>,

    /// Qlog writer
    #[cfg(feature = "qlog")]
    qlog: Option<qlog::QlogWriter>,

    /// Unique trace id for debug logging
    trace_id: String,
}

impl Connection {
    /// Create a new QUIC client connection
    #[doc(hidden)]
    pub fn new_client(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        conf: &Config,
    ) -> Result<Self> {
        Connection::new(scid, local, remote, server_name, None, conf)
    }

    /// Create a new QUIC connection
    ///
    /// The `scid` is the local cid for the connection.
    /// The `addr_token` is optional and used to create the server connection. It
    /// is extracted from Initial packet with Token sent by the client connection.
    fn new(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        addr_token: Option<&AddressToken>,
        conf: &Config,
    ) -> Result<Self> {
        let trace_id = format!("CLIENT-{}", scid);

        let path = path::Path::new(local, remote, true, &conf.recovery, &trace_id);

        let cid_limit = conf.local_transport_params.active_conn_id_limit as usize;
        let paths = path::PathMap::new(path, cid_limit, conf.anti_amplification_factor);

        let active_pid = paths.get_active_path_id()?;
        let reset_token = None;
        let cids = cid::ConnectionIdMgr::new(cid_limit, scid, active_pid, reset_token);

        let mut streams = stream::StreamMap::new(
            conf.max_connection_window,
            conf.max_stream_window,
            stream::StreamTransportParams::from(&conf.local_transport_params),
        );
        streams.set_trace_id(&trace_id);

        let mut tls_session = conf.new_tls_session(server_name)?;

        if let Some(tls_config_selector) = &conf.tls_config_selector {
            tls_session.set_config_selector(tls_config_selector.clone());
        }
        tls_session.set_trace_id(&trace_id);

        let mut conn = Connection {
            version: crate::QUIC_VERSION_V1,
            cids,
            spaces: space::PacketNumSpaceMap::new(),
            paths,
            multipath_scheduler: None,
            multipath_conf: conf.multipath.clone(),
            omit_client_initial_scid: conf.omit_client_initial_scid(),
            streams,
            tls_session,
            crypto_streams: Rc::new(RefCell::new(CryptoStreams::new())),
            undecryptable_packets: UndecryptablePackets::new(conf.max_undecryptable_packets),
            peer_transport_params: TransportParams::default(),
            local_transport_params: conf.local_transport_params.clone(),
            recovery_conf: conf.recovery.clone(),
            local_error: None,
            peer_error: None,
            timers: timer::TimerTable::default(),
            flags: BitFlags::default(),
            stats: ConnectionStats::default(),
            odcid: None,
            rscid: None,
            token: None,
            index: None,
            events: EventQueue::default(),
            queues: None,
            context: None,
            #[cfg(feature = "qlog")]
            qlog: None,
            trace_id,
        };

        let write_method = conn.get_write_method();
        conn.tls_session.set_write_method(write_method);

        // When advertising the enable_multipath transport parameter, the
        // endpoint MUST use non-zero source and destination CIDs.
        if conn.cids.zero_length_scid() || conn.cids.zero_length_dcid() {
            conn.local_transport_params.enable_multipath = false;
        }

        // Always advertise initial_source_connection_id (can be zero-length).
        conn.local_transport_params.initial_source_connection_id = Some(conn.cids.get_scid(0)?.cid);
        if let Some(addr_token) = addr_token {
            conn.local_transport_params
                .original_destination_connection_id = addr_token.odcid;
            conn.local_transport_params.retry_source_connection_id = addr_token.rscid;
            conn.flags.insert(DidRetry);
        }
        conn.local_transport_params.stateless_reset_token = reset_token;
        conn.set_transport_params()?;

        // Generate the client's original DCID using configured cid_len.
        let dcid = crate::RandomConnectionIdGenerator::new(conf.cid_len).generate();
        let reset_token = conn.peer_transport_params.stateless_reset_token;
        conn.set_initial_dcid(dcid, reset_token, active_pid)?;

        conn.tls_session
            .derive_initial_secrets(&dcid, conn.version)?;
        conn.flags.insert(DerivedInitialSecrets);

        if !conf.max_handshake_timeout.is_zero() {
            conn.timers.set(
                Timer::Handshake,
                time::Instant::now() + conf.max_handshake_timeout,
            );
        }

        Ok(conn)
    }

    /// Configure the given session data for resumption.
    pub fn set_session(&mut self, mut buf: &[u8]) -> Result<()> {
        let session_len = buf.read_u64()? as usize;
        let session_bytes = buf.read(session_len)?;
        self.tls_session.set_session(&session_bytes)?;

        let params_len = buf.read_u64()? as usize;
        let params_bytes = buf.read(params_len)?;
        let (peer_params, _) = TransportParams::decode(&params_bytes)?;
        self.set_peer_trans_params(peer_params)?;

        Ok(())
    }

    /// Set address token used by the client connection.
    pub fn set_token(&mut self, token: Vec<u8>) -> Result<()> {
        self.token = Some(token);
        Ok(())
    }

    /// Set keylog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    pub fn set_keylog(&mut self, writer: Box<dyn std::io::Write + Send + Sync>) {
        self.tls_session.set_keylog(writer);
    }

    /// Set qlog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    pub fn set_qlog(
        &mut self,
        writer: Box<dyn std::io::Write + Send + Sync>,
        title: String,
        description: String,
    ) {
        let trace = qlog::TraceSeq::new(
            Some(title.to_string()),
            Some(description.to_string()),
            None,
            qlog::VantagePoint::new(None),
        );
        let level = events::EventImportance::Extra;
        let mut writer = qlog::QlogWriter::new(
            Some(title),
            Some(description),
            trace,
            level,
            writer,
            time::Instant::now(),
        );
        writer.start().ok();

        // Write TransportParametersSet event to qlog
        Self::qlog_quic_params_set(
            &mut writer,
            &self.local_transport_params,
            events::Owner::Local,
            self.tls_session.cipher(),
        );

        self.qlog = Some(writer);
    }

    /// Process an incoming UDP datagram from the peer.
    ///
    /// On success the number of bytes processed is returned. On error the
    /// connection will be closed with an error code.
    #[doc(hidden)]
    pub fn recv(&mut self, buf: &mut [u8], info: &PacketInfo) -> Result<usize> {
        let len = buf.len();
        if len == 0 {
            return Err(Error::NoError);
        }

        // Check path of incoming datagram
        let pid = self.paths.get_path_id(&(info.dst, info.src)); // (local, remote)
        if pid.is_none() {
            // If a client receives packets from an unknown address, it
            // discards these invalid packets.
            trace!(
                "{} client drop packet with unknown addr {:?}",
                self.trace_id, info
            );
            return Ok(len);
        }

        // Process each QUIC packet in the UDP datagram
        let mut left = len;
        while left > 0 {
            let read = match self.recv_packet(&mut buf[(len - left)..len], info, pid) {
                Ok(s) => s,
                Err(Error::Done) => left, // stop and skip the remaining data
                Err(e) => {
                    self.close(false, e.to_wire(), b"").ok(); // close connection
                    info!("{} recv error and close {:?}", self.trace_id, e);
                    return Err(e);
                }
            };
            left -= read;
        }

        // Try to process undecryptable packets
        if !self.is_established() {
            self.try_process_undecryptable_packets();
        }

        Ok(len - left)
    }

    /// Process an incoming QUIC packet from the peer.
    fn recv_packet(
        &mut self,
        buf: &mut [u8],
        info: &PacketInfo,
        pid: Option<usize>,
    ) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::Done);
        }
        let now = time::Instant::now();

        // Check close status of connection
        if self.is_closing() || self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        // Parse header of the QUIC packet
        let (mut hdr, mut read) =
            PacketHeader::from_bytes(buf, self.scid()?.len()).map_err(|_| Error::Done)?;

        // Process Version Negotiation packet
        if hdr.pkt_type == PacketType::VersionNegotiation {
            return self.process_version_negotiation(&hdr, &buf[read..], info.time);
        }

        // Process Retry packet
        if hdr.pkt_type == PacketType::Retry {
            return self.process_retry(&hdr, buf, info.time);
        }

        if hdr.pkt_type != PacketType::OneRTT && hdr.version != self.version {
            return Err(Error::Done);
        }

        // Create new path if need.
        let pid = if hdr.pkt_type == PacketType::OneRTT && self.flags.contains(HandshakeCompleted) {
            self.get_or_create_path(pid, &hdr.dcid, info, buf.len())?
        } else {
            // Use the initial path during handshake.
            self.paths.get_active_path_id()?
        };

        // Get length of pakcet number field and packet payload
        let length = if hdr.pkt_type == PacketType::OneRTT {
            // A packet with a short header does not include a length field, so it
            // can only be the last packet included in a UDP datagram.
            buf.len() - read
        } else {
            let mut b = &buf[read..];
            let len = b.read_varint().map_err(|_| Error::Done)?;
            read = buf.len() - b.len();
            // Make sure the length field is valid.
            if len > b.len() as u64 {
                return Err(Error::Done);
            }
            len as usize
        };
        let pkt_num_offset = read;

        // Derive initial secrets for the server
        if !self.flags.contains(DerivedInitialSecrets) {
            self.tls_session
                .derive_initial_secrets(&hdr.dcid, self.version)?;
            self.flags.insert(DerivedInitialSecrets);
        }

        // Decrypt packet header
        let key = self.tls_session.get_keys(hdr.pkt_type.to_level()?);
        let key = match &key.open {
            Some(open) => open,
            None => {
                let pkt = buf[..read + length].to_vec();
                self.try_buffer_undecryptable_packets(&hdr, pkt, info);
                return Ok(read + length);
            }
        };
        let is_encryption_disabled = self.is_encryption_disabled(hdr.pkt_type);
        packet::decrypt_header(buf, pkt_num_offset, &mut hdr, key, is_encryption_disabled)
            .map_err(|_| Error::Done)?;

        // Decode packet sequence number
        let handshake_confirmed = self.is_confirmed();
        let space_id = self.get_space_id(hdr.pkt_type, pid)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        let largest_rx_pkt_num = space.largest_rx_pkt_num;
        let pkt_num = packet::decode_packet_num(largest_rx_pkt_num, hdr.pkt_num, hdr.pkt_num_len);

        if space.detect_duplicated_pkt_num(pkt_num) {
            trace!(
                "{} ignore duplicated packet {:?}:{}",
                self.trace_id, space_id, pkt_num
            );
            return Err(Error::Done);
        }

        // Select key and decrypt packet payload.
        let payload_offset = pkt_num_offset + hdr.pkt_num_len;
        let payload_len = length.checked_sub(hdr.pkt_num_len).ok_or(Error::Done)?;
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            let (seq, _) = self
                .cids
                .find_scid(&hdr.dcid)
                .ok_or(Error::InvalidState("unknown dcid".into()))?;
            cid_seq = Some(seq as u32)
        }

        let (key, attempt_key_update) = self.tls_session.select_key(
            handshake_confirmed,
            self.flags.contains(EnableMultipath),
            &hdr,
            space,
        )?;
        let mut payload = if !is_encryption_disabled {
            packet::decrypt_payload(buf, payload_offset, payload_len, cid_seq, pkt_num, key)
                .map_err(|_| Error::Done)?
        } else {
            bytes::Bytes::copy_from_slice(&buf[payload_offset..payload_offset + payload_len])
        };
        if payload.is_empty() {
            // An endpoint MUST treat receipt of a packet containing no frames as a connection error
            // of type PROTOCOL_VIOLATION.
            return Err(Error::ProtocolViolation);
        }
        read += length;

        debug!(
            "{} recv packet {:?} pn={} {:?}",
            self.trace_id,
            hdr,
            pkt_num,
            self.paths.get(pid)?
        );

        // Try to update key.
        self.tls_session.try_update_key(
            &mut self.timers,
            space,
            attempt_key_update,
            &hdr,
            now,
            self.paths.max_pto(),
        )?;

        // Update dcid for initial path
        self.try_set_dcid_for_initial_path(pid, &hdr)?;

        // Process each QUIC frame in the QUIC packet
        let mut ack_eliciting_pkt = false;
        let mut probing_pkt = true;
        #[cfg(feature = "qlog")]
        let mut qframes = vec![];

        while !payload.is_empty() {
            let (frame, len) = Frame::from_bytes(&mut payload, hdr.pkt_type)?;
            if frame.ack_eliciting() {
                ack_eliciting_pkt = true;
            }
            if !frame.probing() {
                probing_pkt = false;
            }
            #[cfg(feature = "qlog")]
            if self.qlog.is_some() {
                qframes.push(frame.to_qlog());
            }

            self.recv_frame(frame, &hdr, pid, space_id, info.time)?;
            let _ = payload.split_to(len);
        }

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketReceived event to qlog.
            Self::qlog_quic_packet_received(qlog, &hdr, pkt_num, read, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(pid) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Process acknowledged frames.
        self.try_process_acked_frames();

        // The peer may issue new connection ids. If there is any path waiting
        // for a dcid, try to allocate one for it.
        self.try_allocate_cids_from_peer();

        // Update packet number space
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.recv_pkt_num_need_ack.max() < Some(pkt_num) {
            space.largest_rx_pkt_time = info.time;
        }
        space.recv_pkt_num_win.insert(pkt_num);
        space.recv_pkt_num_need_ack.add_elem(pkt_num);
        space.largest_rx_pkt_num = cmp::max(space.largest_rx_pkt_num, pkt_num);
        if !probing_pkt {
            space.largest_rx_non_probing_pkt_num =
                cmp::max(space.largest_rx_non_probing_pkt_num, pkt_num);
            // TODO: try to do connection migration
        }
        if ack_eliciting_pkt {
            space.largest_rx_ack_eliciting_pkt_num =
                cmp::max(space.largest_rx_ack_eliciting_pkt_num, pkt_num);
        }

        self.try_schedule_ack_frame(space_id, pkt_num, ack_eliciting_pkt)?;

        // An endpoint restarts its idle timer when a packet from its peer is
        // received and processed successfully.
        // See RFC 9000 Section 10.1
        if let Some(idle_timeout) = self.idle_timeout() {
            self.timers.set(Timer::Idle, now + idle_timeout);
        }

        // Update statistic metrics
        self.stats.recv_count += 1;
        self.stats.recv_bytes += read as u64;
        self.paths
            .get_mut(pid)?
            .recovery
            .stat_recv_event(1, read as u64);

        self.flags.insert(NeedSendAckEliciting);

        Ok(read)
    }

    /// Process an incoming QUIC frame from the peer.
    fn recv_frame(
        &mut self,
        frame: Frame,
        hdr: &PacketHeader,
        path_id: usize,
        space_id: SpaceId,
        now: time::Instant,
    ) -> Result<()> {
        debug!("{} recv frame {:?}", self.trace_id, &frame);
        match frame {
            Frame::Paddings { .. } => (), // just ignore

            Frame::Ping { .. } => (), // just ignore

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ..
            } => {
                // ACK Delay is decoded by multiplying the value in the field
                // by 2 to the power of the ack_delay_exponent transport
                // parameter sent by the sender of the ACK frame.
                let mul = 2_u64.pow(self.peer_transport_params.ack_delay_exponent as u32);
                let ack_delay = ack_delay
                    .checked_mul(mul)
                    .ok_or(Error::FrameEncodingError)?;

                if space_id == SpaceId::Handshake {
                    self.flags.insert(PeerVerifiedInitialAddress);
                }
                if space_id == SpaceId::Data && self.is_established() {
                    self.flags.insert(PeerVerifiedInitialAddress);
                    // A client MAY consider the handshake to be confirmed when
                    // it receives an acknowledgment for a 1-RTT packet. This
                    // can be implemented by recording the lowest packet number
                    // sent with 1-RTT keys and comparing it to the Largest
                    // Acknowledged field in any received 1-RTT ACK frame
                    // See RFC 9001 Section 4.1.2
                    let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
                    if ack_ranges.max() > Some(space.lowest_1rtt_pkt_num) {
                        self.flags.insert(HandshakeConfirmed);
                    }
                }

                // Process acknowledgement
                let handshake_status = self.handshake_status();
                let path = self.paths.get_mut(path_id)?;
                let (lost_pkts, lost_bytes) = path.recovery.on_ack_received(
                    &ack_ranges,
                    ack_delay,
                    space_id,
                    &mut self.spaces,
                    handshake_status,
                    #[cfg(feature = "qlog")]
                    self.qlog.as_mut(),
                    now,
                )?;
                self.stats.lost_count += lost_pkts;
                self.stats.lost_bytes += lost_bytes;

                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                if self.flags.contains(HandshakeConfirmed) {
                    self.drop_space_state(SpaceId::Handshake, now);
                }
            }

            Frame::Crypto { offset, data, .. } => {
                let level = space_id.to_level();

                // Insert crypto data to the corresponding crypto stream.
                {
                    // Note: The crypto_streams is shared between the QUIC connection and
                    // the TLS session. It may be mutably borrowed during calling
                    // self.tls_session.read(). Do NOT mutably borrrow it again at the
                    // same scope.
                    let mut crypto_streams = self.crypto_streams.borrow_mut();
                    let crypto_stream = crypto_streams.get_mut(level)?;
                    crypto_stream.recv.write(offset, data, false)?;
                }

                // Read crypto data in order and feed it to the TLS session
                let mut crypto_buf = [0; 512];
                loop {
                    let read = {
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        let crypto_stream = crypto_streams.get_mut(level)?;
                        match crypto_stream.recv.read(&mut crypto_buf) {
                            Ok((read, _)) => read,
                            _ => break,
                        }
                    };

                    let r = self.tls_session.provide(level, &crypto_buf[..read]);
                    self.process_tls_session(r)?;
                }
            }

            Frame::HandshakeDone => {
                self.flags.insert(PeerVerifiedInitialAddress);
                self.flags.insert(HandshakeConfirmed);
                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                self.drop_space_state(SpaceId::Handshake, now);
            }

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                if self.cids.zero_length_dcid() {
                    // An endpoint that is sending packets with a zero-length
                    // Destination CID MUST treat receipt of a NEW_CONNECTION_ID
                    // frame as a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Add a new dcid and retire the specified dcids
                let retired_dcids = self.cids.add_dcid(
                    conn_id,
                    seq_num,
                    u128::from_be_bytes(reset_token.0),
                    retire_prior_to,
                )?;
                self.events.add(Event::DcidAdvertised(reset_token));

                // Try to assign unused dcids to the affected paths
                for (dcid_seq, pid) in retired_dcids {
                    let path = self.paths.get_mut(pid)?;
                    if path.dcid_seq != Some(dcid_seq) {
                        continue;
                    }
                    if let Some(new_dcid_seq) = self.cids.lowest_unused_dcid_seq() {
                        path.dcid_seq = Some(new_dcid_seq);
                        self.cids.mark_dcid_used(new_dcid_seq, pid)?;
                    } else {
                        path.dcid_seq = None; // wait for a new DCID from peer
                    }
                }
            }

            Frame::RetireConnectionId { seq_num } => {
                if self.cids.zero_length_scid() {
                    // An endpoint that provides a zero-length connection ID
                    // MUST treat receipt of a RETIRE_CONNECTION_ID frame as
                    // a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Remove the connection route entry on the endpoint
                match self.cids.get_scid(seq_num) {
                    Ok(c) => self.events.add(Event::ScidRetired(c.cid)),
                    Err(_) => return Ok(()),
                };

                if let Some(pid) = self.cids.retire_scid(seq_num, &hdr.dcid)? {
                    let path = self.paths.get_mut(pid)?;
                    if path.scid_seq == Some(seq_num) {
                        path.scid_seq = None;
                    }
                }
            }

            Frame::PathChallenge { data } => {
                self.paths.on_path_chal_received(path_id, data);
            }

            Frame::PathResponse { data } => {
                if self.paths.on_path_resp_received(path_id, data) {
                    // Notify the path event to the multipath scheduler
                    if let Some(ref mut scheduler) = self.multipath_scheduler {
                        scheduler.on_path_updated(&mut self.paths, PathEvent::Validated(path_id));
                    }
                }
            }

            frame::Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => { // temparaily ignore
            }

            frame::Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
            } => { // temparaily ignore
            }

            Frame::NewToken { token } => {
                self.events.add(Event::NewToken(token));
            }

            // After receiving a CONNECTION_CLOSE frame, endpoints enter the
            // draining state. While otherwise identical to the closing state,
            // an endpoint in the draining state MUST NOT send any packets.
            Frame::ConnectionClose {
                error_code, reason, ..
            } => {
                self.peer_error = Some(ConnectionError {
                    is_app: false,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }
            Frame::ApplicationClose { error_code, reason } => {
                self.peer_error = Some(ConnectionError {
                    is_app: true,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                data,
            } => {
                self.streams
                    .on_stream_frame_received(stream_id, offset, length, fin, data)?;
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                self.streams
                    .on_reset_stream_frame_received(stream_id, error_code, final_size)?;
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                self.streams
                    .on_stop_sending_frame_received(stream_id, error_code)?;
            }

            Frame::MaxData { max } => {
                self.streams.on_max_data_frame_received(max);
            }

            Frame::MaxStreamData { stream_id, max } => {
                self.streams
                    .on_max_stream_data_frame_received(stream_id, max)?;
            }

            Frame::MaxStreams { bidi, max } => {
                self.streams.on_max_streams_frame_received(max, bidi)?;
            }

            Frame::DataBlocked { max } => {
                self.streams.on_data_blocked_frame_received(max);
            }

            Frame::StreamDataBlocked { stream_id, max } => {
                self.streams
                    .on_stream_data_blocked_frame_received(stream_id, max)?;
            }

            Frame::StreamsBlocked { bidi, max } => {
                self.streams.on_streams_blocked_frame_received(max, bidi)?;
            }
        }

        Ok(())
    }

    /// Process the incoming Version Negotiation packet.
    fn process_version_negotiation(
        &mut self,
        pkt_hdr: &PacketHeader,
        mut payload: &[u8],
        now: time::Instant,
    ) -> Result<usize> {
        if self.flags.contains(DidVersionNegotiation) {
            return Err(Error::Done);
        }

        // A client MUST discard any Version Negotiation packet if it has
        // received and successfully processed any other packet, including an
        // earlier Version Negotiation packet.
        if self.stats.recv_count > 0 {
            return Err(Error::Done);
        }

        // The sever must echo both CIDs gives clients some assurance that the
        // server received the packet and that the Version Negotiation packet
        // was not generated by an entity that did not observe the Initial packet.
        if pkt_hdr.dcid != self.scid()? {
            return Err(Error::Done);
        }
        if pkt_hdr.scid != self.dcid()? {
            return Err(Error::Done);
        }

        let mut found_version = 0;
        while !payload.is_empty() {
            let version = payload.read_u32().map_err(|_| Error::Done)?;
            if crate::version_is_supported(version) {
                found_version = cmp::max(found_version, version);
            }
        }

        if found_version == 0 {
            return Err(Error::UnknownVersion);
        }

        // A client MUST discard a Version Negotiation packet that lists the
        // QUIC version selected by the client.
        if found_version == self.version {
            return Err(Error::Done);
        }

        self.version = found_version;
        self.flags.insert(DidVersionNegotiation);
        self.flags.remove(GotPeerCid);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;
        self.set_transport_params()?;

        // Derive Initial secrets based on the new version.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Process the incoming RETRY packet.
    fn process_retry(
        &mut self,
        pkt_hdr: &PacketHeader,
        pkt_buf: &mut [u8],
        now: time::Instant,
    ) -> Result<usize> {
        // A client MUST accept and process at most one Retry packet for each
        // connection attempt. After the client has received and processed an
        // Initial or Retry packet from the server, it MUST discard any
        // subsequent Retry packets that it receives.
        if self.flags.contains(DidRetry) {
            return Err(Error::Done);
        }

        // Clients MUST discard Retry packets that have a Retry Integrity Tag
        // that cannot be validated. This diminishes an attacker's ability to
        // inject a Retry packet and protects against accidental corruption of
        // Retry packets.
        if packet::verify_retry_integrity_tag(pkt_buf, &self.dcid()?, self.version).is_err() {
            return Err(Error::Done);
        }

        self.token.clone_from(&pkt_hdr.token);
        self.flags.insert(DidRetry);
        self.flags.remove(GotPeerCid);

        // A client sets the Destination Connection ID field of this Initial
        // packet to the value from the Source Connection ID field in the Retry
        // packet.
        self.odcid = Some(self.dcid()?);
        self.set_initial_dcid(pkt_hdr.scid, None, self.paths.get_active_path_id()?)?;
        self.rscid = Some(self.dcid()?);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;

        // Changing the Destination Connection ID field also results in a
        // change to the keys used to protect the Initial packet.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Check and record handshake status.
    fn process_tls_session(&mut self, tls_result: Result<()>) -> Result<()> {
        if self.flags.contains(HandshakeCompleted) {
            return tls_result;
        }

        match tls_result {
            Ok(_) => (),
            Err(Error::Done) => {
                // Try to parse transport parameters as soon as the first flight data is processed.
                let peer_params = self.tls_session.peer_transport_params();
                if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
                    let (peer_params, _) = TransportParams::decode(peer_params)?;
                    self.process_peer_trans_params(peer_params)?;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        let peer_params = self.tls_session.peer_transport_params();
        if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
            let (peer_params, _) = TransportParams::decode(peer_params)?;
            self.process_peer_trans_params(peer_params)?;
        }

        if self.tls_session.is_completed() {
            self.flags.insert(HandshakeCompleted);
            self.events.add(Event::ConnectionEstablished);
            self.timers.stop(Timer::Handshake);
            self.try_process_undecryptable_packets();

            // Try to promote to multipath mode.
            if self.peer_transport_params.enable_multipath
                && self.local_transport_params.enable_multipath
            {
                // If an enable_multipath transport parameter is received and
                // the carrying packet contains a zero length connection ID,
                // the receiver MUST treat this as a connection error.
                if self.cids.zero_length_dcid() {
                    return Err(Error::MultipathProtocolViolation);
                }

                self.multipath_scheduler = Some(build_multipath_scheduler(&self.multipath_conf));
                self.paths.enable_multipath();
                self.flags.insert(EnableMultipath);
                debug!("{} enable multipath", &self.trace_id);
            }

            // Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
            self.try_schedule_control_frames();
        }

        Ok(())
    }

    /// Validate and apply transport parameters advertised by the peer.
    fn process_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        // Validate cid related transport parameters
        if peer_params.initial_source_connection_id != Some(self.dcid()?) {
            return Err(Error::TransportParameterError);
        }
        if peer_params.original_destination_connection_id != self.odcid {
            return Err(Error::TransportParameterError);
        }
        if peer_params.retry_source_connection_id != self.rscid {
            return Err(Error::TransportParameterError);
        }

        // The remote server can issue a stateless_reset_token transport parameter
        // that applies to the connection ID that it selected during the handshake.
        if let Some(reset_token) = peer_params.stateless_reset_token {
            let reset_token = ResetToken::from_u128(reset_token);
            self.events.add(Event::ResetTokenAdvertised(reset_token));
        }

        // The connection enters disable_1rtt_encryption mode
        if peer_params.disable_encryption && self.local_transport_params.disable_encryption {
            self.flags.insert(DisableEncryption);
            debug!(
                "{} encryption on 1-RTT packets has been negotiated to be disabled",
                self.trace_id
            );
        }

        self.set_peer_trans_params(peer_params)?;
        self.flags.insert(AppliedPeerTransportParams);

        // Write TransportParametersSet event to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            Self::qlog_quic_params_set(
                qlog,
                &self.peer_transport_params,
                events::Owner::Remote,
                self.tls_session.cipher(),
            );
        }

        Ok(())
    }

    /// Set transport parameters advertised by the peer
    fn set_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        trace!(
            "{} set peer transport parameters {:?}",
            self.trace_id, peer_params
        );

        self.streams
            .update_peer_stream_transport_params(stream::StreamTransportParams::from(&peer_params));

        let active_path = self.paths.get_active_mut()?;
        let max_ack_delay = time::Duration::from_millis(peer_params.max_ack_delay);
        active_path.recovery.max_ack_delay = max_ack_delay;

        let max_datagram_size = peer_params.max_udp_payload_size as usize;
        active_path
            .recovery
            .update_max_datagram_size(max_datagram_size, true);

        self.cids.set_scid_limit(peer_params.active_conn_id_limit);

        self.peer_transport_params = peer_params;
        Ok(())
    }

    /// Set peer context for the specific path
    pub fn set_path_peer_context<T: Any + Send + Sync>(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ctx: T,
    ) -> Result<()> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        path.set_peer_context(ctx);
        Ok(())
    }

    /// Get peer context for the specific path
    pub fn path_peer_context(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<Option<&mut dyn Any>> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        Ok(path.peer_context())
    }

    /// Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
    fn try_schedule_control_frames(&mut self) {
        // An endpoint SHOULD ensure that its peer has a sufficient number of
        // available and unused connection IDs. An endpoint MUST NOT provide
        // more connection IDs than the peer's limit.
        let id_limit = cmp::min(
            self.peer_transport_params.active_conn_id_limit,
            crate::MAX_CID_LIMIT,
        );
        let num = (id_limit - 1) as u8;
        self.events.add(Event::ScidToAdvertise(num));
    }

    /// Try to buffer undecryptable packets when the keys are not yet available.
    fn try_buffer_undecryptable_packets(
        &mut self,
        hdr: &PacketHeader,
        pkt: Vec<u8>,
        info: &PacketInfo,
    ) {
        if self.is_established()
            || (hdr.pkt_type != PacketType::Handshake && hdr.pkt_type != PacketType::OneRTT)
        {
            trace!("{} drop packet {:?}", self.trace_id, hdr);
            return;
        }

        if self.undecryptable_packets.push(&hdr.pkt_type, pkt, info) {
            trace!("{} buffer undecryptable packets: {:?}", self.trace_id, hdr);
        } else {
            trace!(
                "{} key not yet available, drop packet {:?}",
                self.trace_id, hdr
            );
        }
    }

    /// Try to process undecryptable packets.
    fn try_process_undecryptable_packets(&mut self) {
        if self.undecryptable_packets.all_empty() {
            return;
        }

        let pkt_types = vec![PacketType::Handshake, PacketType::OneRTT];

        for pkt_type in pkt_types {
            if self.undecryptable_packets.is_empty(&pkt_type) {
                continue;
            }

            let level = pkt_type.to_level().unwrap();
            let key = self.tls_session.get_keys(level);
            if key.open.is_none() {
                continue;
            }

            while let Some((mut pkt, info)) = self.undecryptable_packets.pop(&pkt_type) {
                if let Err(e) = self.recv(&mut pkt, &info) {
                    error!(
                        "{} try process undecryptable packet error {:?} type {:?}",
                        self.trace_id, e, pkt_type
                    );
                }
            }
        }
    }

    /// Check and schedule an ACK frame to acknowledge incoming packets.
    fn try_schedule_ack_frame(
        &mut self,
        space_id: SpaceId,
        pkt_num: u64,
        ack_eliciting: bool,
    ) -> Result<()> {
        if !ack_eliciting {
            return Ok(());
        }

        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.need_send_ack {
            return Ok(());
        }

        // An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        // packets immediately
        if space.id == SpaceId::Initial || space.id == SpaceId::Handshake {
            space.need_send_ack = true;
            return Ok(());
        }

        // A receiver SHOULD send an ACK frame after receiving at least two
        // ack-eliciting packets.
        space.ack_eliciting_pkts_since_last_sent_ack += 1;
        let ack_eliciting_threshold = self.recovery_conf.ack_eliciting_threshold;
        if space.ack_eliciting_pkts_since_last_sent_ack >= ack_eliciting_threshold {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // In order to assist loss detection at the sender, an endpoint SHOULD
        // generate and send an ACK frame without delay when it receives an
        // ack-eliciting packet either:
        // - when the received packet has a packet number less than another
        //   ack-eliciting packet that has been received, or
        // - when the packet has a packet number larger than the highest-numbered
        // ack-eliciting packet that has been received and there are missing
        // packets between that packet and this packet.
        if pkt_num < space.largest_rx_ack_eliciting_pkt_num
            || pkt_num > space.largest_rx_ack_eliciting_pkt_num + 1
        {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // All ack-eliciting 0-RTT and 1-RTT packets within its advertised
        // max_ack_delay.
        if space.ack_timer.is_none() {
            let ack_delay = time::Duration::from_millis(self.peer_transport_params.max_ack_delay);
            space.ack_timer = Some(time::Instant::now() + ack_delay);
            debug!(
                "{} set ack timer for space {:?}, timeout {:?} ",
                &self.trace_id, space_id, space.ack_timer
            );
        }
        Ok(())
    }

    /// Process acknowledged frames in each packet number space
    fn try_process_acked_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for acked_frame in space.acked.drain(..) {
                match acked_frame {
                    // When a packet containing an ACK frame is acknowledged by
                    // the peer, the endpoint can stop acknowledging packets
                    // less than or equal to the Largest Acknowledged field in
                    // the sent ACK frame.
                    Frame::Ack { ack_ranges, .. } => {
                        if let Some(largest_acked) = ack_ranges.max() {
                            space.recv_pkt_num_need_ack.remove_until(largest_acked);
                        }
                    }

                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.ack_and_drop(offset, length);
                        }
                    }

                    // HandshakeDone has been successfully deliveried to client.
                    Frame::HandshakeDone => {
                        self.flags.remove(NeedSendHandshakeDone);
                        self.flags.insert(HandshakeDoneAcked);
                    }

                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_acked(stream_id, offset, length);

                        // Write QuicStreamDataMoved event to qlog
                        #[cfg(feature = "qlog")]
                        if let Some(qlog) = &mut self.qlog {
                            Self::qlog_quic_data_acked(qlog, stream_id, offset, length);
                        }
                    }

                    Frame::ResetStream { stream_id, .. } => {
                        self.streams.on_reset_stream_frame_acked(stream_id);
                    }

                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_acked(probe_size, peer_mds);
                            let current = path.dplpmtud.get_current_size();
                            path.recovery.update_max_datagram_size(current, false);
                            debug!("{} path {:?} MTU is {} now", self.trace_id, path, current);
                        }
                    }

                    _ => (),
                }
            }
        }
    }

    /// If any path doesn't has a DCID, try to allocate one for it.
    fn try_allocate_cids_from_peer(&mut self) {
        let paths_no_dcid = self.paths.iter_mut().filter(|(_, p)| p.dcid_seq.is_none());

        for (pid, path) in paths_no_dcid {
            if self.cids.zero_length_dcid() {
                path.dcid_seq = Some(0);
                continue;
            }

            let dcid_seq = match self.cids.lowest_unused_dcid_seq() {
                Some(seq) => seq,
                None => break,
            };
            let _ = self.cids.mark_dcid_used(dcid_seq, pid); // alaways success
            path.dcid_seq = Some(dcid_seq);
        }
    }

    /// Get the maximum datagram size of the given path.
    pub(crate) fn max_datagram_size(&self, pid: usize) -> usize {
        // The peer's `max_udp_payload_size` transport parameter limits the
        // size of UDP payloads that it is willing to receive. Therefore,
        // prior to receiving that parameter, we only use the default value.
        if !self.flags.contains(AppliedPeerTransportParams) {
            return crate::MIN_CLIENT_INITIAL_LEN;
        }

        // Use the validated max_datagram_size
        self.paths
            .get(pid)
            .ok()
            .map_or(crate::MIN_CLIENT_INITIAL_LEN, |path| {
                path.recovery.max_datagram_size
            })
    }

    /// Write coalesced multiple QUIC packets to the given buffer which will
    /// then be sent to the peer.
    ///
    /// The size of `out` should be at least 1200 bytes, ideally matching or
    /// exceeding the maximum possible MTU.
    ///
    /// Return Error::Done if no packet can be sent.
    pub(crate) fn send(&mut self, out: &mut [u8]) -> Result<(usize, PacketInfo)> {
        if out.len() < crate::MIN_CLIENT_INITIAL_LEN {
            return Err(Error::BufferTooShort);
        }

        // Check close status of connection
        if self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        if !self.flags.contains(DerivedInitialSecrets) {
            return Err(Error::Done);
        }

        if !self.flags.contains(InitiatedClientHandshake) {
            match self.tls_session.process() {
                Ok(_) => {}
                Err(Error::Done) => {}
                Err(e) => {
                    return Err(e);
                }
            };
            self.flags.insert(InitiatedClientHandshake);
        }

        // Process all lost frames and prepare for retransmitting
        self.process_all_lost_frames();

        // Select a path for sending a packet
        let pid = self.select_send_path()?;

        // Limit bytes sent by path MTU limit and server send limit before address validation
        let mut left = cmp::min(out.len(), self.max_datagram_size(pid));

        let mut done = 0;

        // Write QUIC packets to the buffer
        let mut has_initial = false;
        while left > 0 {
            let (pkt_type, is_pmtu_probe, written) =
                match self.send_packet(&mut out[done..], left, pid, done == 0, has_initial) {
                    Ok(v) => v,
                    Err(Error::BufferTooShort) | Err(Error::Done) => break,
                    Err(e) => return Err(e),
                };

            left = left.saturating_sub(written);
            done = done.saturating_add(written);

            match pkt_type {
                PacketType::Initial => has_initial = true,

                // A packet with a short header does not include a length, so it
                // can only be the last packet included in a UDP datagram.
                PacketType::OneRTT => break,

                _ => (),
            }

            // The PMTU probe is not coalesced with other packets, since packets
            // that are larger than the current maximum datagram size are more
            // likely to be dropped by the network.
            if is_pmtu_probe {
                break;
            }
        }

        if done == 0 {
            return Err(Error::Done);
        }

        // Sending UDP datagrams carrying Initial packets of this size ensures
        // that the network path supports a reasonable Path Maximum Transmission
        // Unit (PMTU), in both directions. Initial packets can even be coalesced
        // with invalid packets, which a receiver will discard.
        // See RFC 9000 Section 14.1
        if has_initial && left > 0 && done < crate::MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, crate::MIN_CLIENT_INITIAL_LEN - done);
            out[done..done + pad_len].fill(0);
            done += pad_len;
        }

        let path = self.paths.get(pid)?;
        let info = PacketInfo {
            src: path.local_addr(),
            dst: path.remote_addr(),
            time: time::Instant::now(),
        };
        Ok((done, info))
    }

    /// Write a QUIC packet to the given buffer.
    ///
    /// The `out` is the write buffer with a size that must be no less than `left`.
    /// The `left` is the upper limit for the write size when sending a non-PMTU
    /// probe packet.
    /// The `path_id` is the selected path for sending out packets.
    /// The `first` indicates that it is the first packet being written to the UDP
    /// datagram.
    /// The `has_initial` indicates that a previous Initial packet has been written
    /// the UDP datagram.
    ///
    /// Return a tuple consisting of the packet type, PMUT probe flag, and the
    /// packet size upon success.
    /// Return `Error::BufferTooShort` if the input buffer is too small to
    /// write a single QUIC packet.
    /// Return `Error::Done` if no packet can be sent.
    /// Return other Error if found unexpected error.
    fn send_packet(
        &mut self,
        out: &mut [u8],
        mut left: usize,
        path_id: usize,
        first: bool,
        has_initial: bool,
    ) -> Result<(PacketType, bool, usize)> {
        let now = time::Instant::now();

        if out.len() < left {
            return Err(Error::InvalidState("buffer too short".into()));
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        // Select packet type and encryption level
        let pkt_type = self.select_send_packet_type(path_id)?;
        let level = pkt_type.to_level()?;

        // Prepare and encode packet header (except for the Length and Packet Number field)
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let (pkt_num, pkt_num_len) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            let largest_acked = space.get_largest_acked_pkt();
            let pkt_num = space.next_pkt_num;
            let pkt_num_len = packet::packet_num_len(pkt_num, largest_acked);
            (pkt_num, pkt_num_len)
        };

        let dcid_seq = self
            .paths
            .get(path_id)?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let dcid = self.cids.get_dcid(dcid_seq)?.cid;

        let scid = if pkt_type == PacketType::Initial && self.omit_client_initial_scid {
            // Omit SCID in client Initial
            ConnectionId::default()
        } else if let Some(scid_seq) = self.paths.get(path_id)?.scid_seq {
            self.cids.get_scid(scid_seq)?.cid
        } else if pkt_type == PacketType::OneRTT {
            ConnectionId::default()
        } else {
            return Err(Error::InternalError);
        };

        let hdr = PacketHeader {
            pkt_type,
            version: self.version,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len,
            token: if pkt_type == PacketType::Initial {
                // Note: Retry packet is not sent by send_packet()
                self.token.clone()
            } else {
                None
            },
            key_phase: self.tls_session.current_key_phase(),
        };
        let hdr_offset = hdr.to_bytes(&mut out[..left])?;

        // Check the size of remaining space of the buffer
        let mut pkt_num_offset = hdr_offset;
        if pkt_type != PacketType::OneRTT {
            pkt_num_offset += crate::LENGTH_FIELD_LEN; // Reserved for Packet length field
        }
        let crypto_overhead = match self.tls_session.get_overhead(level) {
            Some(v) => v,
            // Keys for this level are not ready yet – nothing to send now.
            None => return Err(Error::Done),
        };
        let total_overhead = if !self.is_encryption_disabled(hdr.pkt_type) {
            pkt_num_offset + pkt_num_len + crypto_overhead
        } else {
            pkt_num_offset + pkt_num_len
        };

        match left.checked_sub(total_overhead) {
            Some(val) => left = val,
            None => {
                return Err(Error::BufferTooShort);
            }
        }
        if left < crate::MIN_PAYLOAD_LEN {
            return Err(Error::BufferTooShort);
        }

        // Encode packet number
        let len = packet::encode_packet_num(
            pkt_num,
            pkt_num_len,
            &mut out[pkt_num_offset..pkt_num_offset + pkt_num_len],
        )?;
        let payload_offset = pkt_num_offset + len;

        // Write frames into the packet payload
        let (ack_elicit_required, is_probe) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            (space.need_elicit_ack(), space.loss_probes > 0)
        };
        let mut write_status = FrameWriteStatus {
            ack_elicit_required,
            is_probe,
            overhead: total_overhead,
            ..FrameWriteStatus::default()
        };

        match self.send_frames(
            &mut out[payload_offset..],
            left,
            &mut write_status,
            pkt_type,
            path_id,
            first,
            has_initial,
        ) {
            Ok(..) => (),
            Err(Error::Done) if write_status.written > 0 => (), // at least one frame was written
            Err(e) => return Err(e),
        };

        // Fill in Length field of the packet header. This is the length of the
        // remainder of the packet (that is, the Packet Number and Payload
        // fields) in bytes
        let payload_len = write_status.written;
        if pkt_type != PacketType::OneRTT {
            // Note: This type of packet is always encrypted, even if the disable_1rtt_encryption
            // transport parameter is successfully negotiated.
            let len = pkt_num_len + payload_len + crypto_overhead;
            let mut out = &mut out[hdr_offset..];
            out.write_varint_with_len(len as u64, crate::LENGTH_FIELD_LEN)?;
        }

        // Encrypt the packet header fields and payload
        let key = self.tls_session.get_keys(pkt_type.to_level()?);
        let key = match &key.seal {
            Some(seal) => seal,
            // Seal key not ready; defer sending for now.
            None => return Err(Error::Done),
        };
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            cid_seq = Some(dcid_seq as u32);
        }

        let written = if !self.is_encryption_disabled(hdr.pkt_type) {
            packet::encrypt_packet(
                out,
                cid_seq,
                pkt_num,
                pkt_num_len,
                payload_len,
                payload_offset,
                None,
                key,
            )?
        } else {
            payload_offset + payload_len
        };

        let sent_pkt = space::SentPacket {
            pkt_type,
            pkt_num,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            sent_size: written,
            ack_eliciting: write_status.ack_eliciting,
            in_flight: write_status.in_flight,
            has_data: write_status.has_data,
            pmtu_probe: write_status.is_pmtu_probe,
            pacing: write_status.pacing,
            frames: write_status.frames,
            rate_sample_state: Default::default(),
            buffer_flags: write_status.buffer_flags,
        };
        debug!(
            "{} sent packet {:?} {:?} {:?}",
            self.trace_id,
            hdr,
            &sent_pkt,
            self.paths.get(path_id)?
        );

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketSent event to qlog.
            let mut qframes = Vec::with_capacity(sent_pkt.frames.len());
            for frame in &sent_pkt.frames {
                qframes.push(frame.to_qlog());
            }
            Self::qlog_quic_packet_sent(qlog, &hdr, pkt_num, written, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(path_id) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Notify the packet sent event to the multipath scheduler
        if let Some(ref mut scheduler) = self.multipath_scheduler {
            scheduler.on_sent(
                &sent_pkt,
                now,
                path_id,
                &mut self.paths,
                &mut self.spaces,
                &mut self.streams,
            );
        }

        // TODO: check app limited
        // if write_status.in_flight == true and check app limited

        let handshake_status = self.handshake_status();
        self.paths.get_mut(path_id)?.recovery.on_packet_sent(
            sent_pkt,
            space_id,
            &mut self.spaces,
            handshake_status,
            now,
        );

        if let Some(data) = write_status.challenge {
            // Record packet size and loss time if a PATH_CHALLENGE is sent.
            self.paths.on_path_chal_sent(path_id, data, written, now)?;
        }

        if write_status.is_pmtu_probe {
            self.paths
                .get_mut(path_id)?
                .dplpmtud
                .on_pmtu_probe_sent(written);
        }

        // Update connection state and statistic metrics
        self.stats.sent_count += 1;
        self.stats.sent_bytes += written as u64;
        self.paths
            .get_mut(path_id)?
            .recovery
            .stat_sent_event(1, written as u64);
        {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            space.next_pkt_num += 1;
            if pkt_type == PacketType::OneRTT {
                let lowest_1rtt_pkt_num = space.lowest_1rtt_pkt_num;
                space.lowest_1rtt_pkt_num = cmp::min(lowest_1rtt_pkt_num, pkt_num);
                if space.first_pkt_num_sent.is_none() {
                    space.first_pkt_num_sent = Some(pkt_num);
                }
            }
        }

        // The successful use of Handshake packets indicates that no more
        // Initial packets need to be exchanged, as these keys can only be
        // produced after receiving all CRYPTO frames from Initial packets.
        // Thus, a client MUST discard Initial keys when it first sends a
        // Handshake packet
        if pkt_type == PacketType::Handshake {
            self.drop_space_state(SpaceId::Initial, now);
        }

        // An endpoint also restarts its idle timer when sending an ack-eliciting
        // packet if no other ack-eliciting packets have been sent since last
        // receiving and processing a packet.
        if write_status.ack_eliciting
            && !self.flags.contains(SentAckElicitingSinceRecvPkt)
            && let Some(idle_timeout) = self.idle_timeout()
        {
            self.timers.set(Timer::Idle, now + idle_timeout);
        }
        if write_status.ack_eliciting {
            self.flags.insert(SentAckElicitingSinceRecvPkt);
        }

        Ok((pkt_type, write_status.is_pmtu_probe, written))
    }

    /// Write QUIC frames to the payload of a QUIC packet.
    ///
    /// The current write offset in the `out` buffer is recorded in `st.written`
    /// Return Error::Done if there is no frame to send or no left room to write more frames.
    /// Return other Error if found unexpected error.
    #[allow(clippy::too_many_arguments)]
    fn send_frames(
        &mut self,
        buf: &mut [u8],
        left: usize,
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
        has_initial: bool,
    ) -> Result<()> {
        // Write an ACK frame
        self.try_write_ack_frame(&mut buf[..left], st, pkt_type, path_id)?;

        // Write a CONNECTION_CLOSE frame
        self.try_write_close_frame(&mut buf[..left], st, pkt_type, path_id)?;

        let path = self.paths.get_mut(path_id)?;
        path.recovery.stat_cwnd_limited();

        let now = time::Instant::now();
        let r = &mut self.paths.get_mut(path_id)?.recovery;

        // Check the congestion window
        // - Packets containing frames besides ACK or CONNECTION_CLOSE frames
        // count toward congestion control limits. (RFC 9002 Section 3)
        // - Probe packets are allowed to temporarily exceed the congestion
        // window. (RFC 9002 Section 4.7)
        if !st.is_probe && !r.can_send() {
            return Err(Error::Done);
        }
        st.pacing = true;

        // Write PMTU probe frames
        // Note: To probe the path MTU, the write size will exceed `left` but
        // not surpass the length of `buf`.
        self.try_write_pmut_probe_frames(buf, st, pkt_type, path_id, first)?;

        // Since it's not a PMTU probe packet, let's cap the buffer size for
        // simplicity.
        let out = &mut buf[..left];

        // Write PATH_CHALLENGE/PATH_RESPONSE frames
        self.try_write_path_validation_frames(out, st, pkt_type, path_id)?;

        // Write NEW_CONNECTION_ID/RETRIE_CONNECTION_ID frames
        self.try_write_cid_control_frame(out, st, pkt_type, path_id)?;

        // Write stream control frames
        self.try_write_stream_control_frames(out, st, pkt_type, path_id)?;

        // Write a CRYPTO frame
        self.try_write_crypto_frame(out, st, pkt_type, path_id)?;

        // Write buffered frames
        self.try_write_buffered_frames(out, st, pkt_type, path_id)?;

        // Write STREAM frames
        self.try_write_stream_frames(out, st, pkt_type, path_id)?;

        // Write a NEW_TOKEN frame
        self.try_write_new_token_frame(out, st, pkt_type, path_id)?;

        // Write a PING frame
        if ((st.ack_elicit_required && !st.ack_eliciting)
            || self.paths.get_mut(path_id)?.need_send_ping)
            && !self.is_closing()
        {
            let frame = Frame::Ping { pmtu_probe: None };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.paths.get_mut(path_id)?.need_send_ping = false;
        }

        // No frames to be sent
        if st.frames.is_empty() {
            // TODO: set app-limited
            return Err(Error::Done);
        }

        // Write PADDING frames
        if (out.len() - st.written >= 1)
            && (
                // Expand the payload of all UDP datagrams carrying Initial packets to
                // at least the smallest allowed maximum datagram size. Sending UDP
                // datagrams of this size ensures that the network path supports a
                // reasonable Path Maximum Transmission Unit (PMTU), in both directions.
                has_initial
                // To prevent deadlock when the server reaches its anti-amplification
                // limit, clients MUST send a packet on a Probe Timeout (PTO).
                // Specifically, the client MUST send an Initial packet in a UDP datagram
                // that contains at least 1200 bytes if it does not have Handshake keys,
                // and otherwise send a Handshake packet.
                || (st.is_probe && pkt_type == PacketType::Handshake)
                // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE or
                // PATH_RESPONSE frame to at least the smallest allowed maximum datagram
                // size. This verifies that the path is able to carry datagrams of this
                // size in both directions.
                || self.paths.get(path_id)?.need_expand_padding_frames()
            )
        {
            let frame = Frame::Paddings {
                len: out.len() - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }
        if st.written < crate::MIN_PAYLOAD_LEN {
            let frame = Frame::Paddings {
                len: crate::MIN_PAYLOAD_LEN - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }

        Ok(())
    }

    /// Write PATH_RESPONSE/PATH_CHALLENGE frames if needed.
    fn try_write_path_validation_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT {
            return Ok(());
        }

        // Create PATH_RESPONSE frame if needed.
        while let Some(challenge) = self.paths.get_mut(path_id)?.pop_recv_chal() {
            let frame = Frame::PathResponse { data: challenge };

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
        }

        // Create PATH_CHALLENGE frame if needed.
        if self.paths.get(path_id)?.path_chal_initiated() {
            let data = rand::random::<u64>().to_be_bytes();
            let frame = Frame::PathChallenge { data };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            st.challenge = Some(data);
        }

        Ok(())
    }

    /// Write PMTU probe frames if needed.
    fn try_write_pmut_probe_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || !self.flags.contains(HandshakeCompleted)
            || self.is_closing()
            || !first
            || !st.frames.is_empty()
        {
            return Ok(());
        }

        let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
        let path = self.paths.get_mut(path_id)?;
        let probe_size = path.dplpmtud.get_probe_size(peer_mds);
        if !path.validated()
            || !path.dplpmtud.should_probe()
            || probe_size > buf.len()
            || (probe_size as u64) > path.recovery.congestion.congestion_window()
            || path.recovery.congestion.in_recovery(time::Instant::now())
        {
            return Ok(());
        }

        // The content of the PMTU probe is limited to PING and PADDING frames.
        let frame = frame::Frame::Ping {
            pmtu_probe: Some((path_id, probe_size)),
        };
        Connection::write_frame_to_packet(frame, buf, st)?;

        let padding_len = probe_size - st.overhead - 1;
        let frame = frame::Frame::Paddings { len: padding_len };
        Connection::write_frame_to_packet(frame, buf, st)?;

        st.ack_eliciting = true;
        st.in_flight = true;
        st.is_pmtu_probe = true;

        // Finish writing the datagram to prevent it from coalescing with other
        // QUIC packets.
        Err(Error::Done)
    }

    /// Populate Acknowledgement frame to packet payload buffer.
    fn try_write_ack_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let is_closing = self.is_closing();
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;

        if space.recv_pkt_num_need_ack.is_empty()
            || !space.need_send_ack
            || is_closing
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        // Create ACK frame if needed.
        let ack_delay_exp = self.local_transport_params.ack_delay_exponent as u32;
        let ack_delay = space.largest_rx_pkt_time.elapsed();
        let ack_delay = ack_delay.as_micros() as u64 / 2_u64.pow(ack_delay_exp);
        let frame = Frame::Ack {
            ack_delay,
            ack_ranges: space.recv_pkt_num_need_ack.clone(),
            ecn_counts: None, // ECN not supported
        };
        Connection::write_frame_to_packet(frame, out, st)?;
        space.need_send_ack = false;
        space.ack_eliciting_pkts_since_last_sent_ack = 0;

        Ok(())
    }

    /// Populate Connection ID control frames to packet payload buffer.
    fn try_write_cid_control_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        // Create NEW_CONNECTION_ID frames as needed.
        while let Some(seq) = self.cids.next_scid_to_advertise() {
            let frame = self.cids.create_new_connection_id_frame(seq)?;

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_scid_to_advertise(seq, false);
        }

        if !self.paths.get(path_id)?.active() {
            return Ok(());
        }

        // Create RETIRE_CONNECTION_ID frames as needed.
        while let Some(seq) = self.cids.next_dcid_to_retire() {
            // The sequence number specified in a RETIRE_CONNECTION_ID frame
            // MUST NOT refer to the Destination Connection ID field of the
            // packet in which the frame is contained.
            let dcid_seq = self
                .paths
                .get(path_id)?
                .dcid_seq
                .ok_or(Error::InternalError)?;
            if seq == dcid_seq {
                continue;
            }

            let frame = Frame::RetireConnectionId { seq_num: seq };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_dcid_to_retire(seq, false);

            if let Ok(cid) = self.cids.get_dcid(seq)
                && let Some(token) = cid.reset_token
            {
                let token = ResetToken(token.to_be_bytes());
                self.events.add(Event::DcidRetired(token));
            }
        }

        Ok(())
    }

    /// Populate Stream control frames to packet payload buffer.
    fn try_write_stream_control_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // STREAM control frames can only be sent in 1-RTT packet.
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if !path.active() {
            return Ok(());
        }

        let now = time::Instant::now();

        // Create MAX_STREAMS frame if needed.
        for bidi in &[true, false] {
            if self.streams.should_update_local_max_streams(*bidi) {
                let frame = frame::Frame::MaxStreams {
                    bidi: *bidi,
                    max: self.streams.max_streams_next(*bidi),
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Apply the new max_streams limit.
                self.streams.update_local_max_streams(*bidi);
            }
        }

        // Create DATA_BLOCKED frame if needed.
        if let Some(blocked_at) = self.streams.data_blocked_at() {
            let frame = frame::Frame::DataBlocked { max: blocked_at };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            // Clear the data_blocked state.
            self.streams.update_data_blocked_at(None);
        }

        // Create MAX_STREAM_DATA frames if needed.
        for stream_id in self.streams.almost_full() {
            let stream = match self.streams.get_mut(stream_id) {
                Some(v) => v,

                None => {
                    // The stream closed, remove it from the almost full set.
                    self.streams.mark_almost_full(stream_id, false);
                    continue;
                }
            };

            // Adjust the stream window size automatically.
            stream
                .recv
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxStreamData {
                stream_id,
                max: stream.recv.max_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            let recv_win = stream.recv.window();
            // Apply the new flow control limit.
            stream.recv.update_max_data(now);
            self.streams.mark_almost_full(stream_id, false);

            // Ensure that the connection window always has some room
            // compared to the stream window.
            self.streams.ensure_window_lower_bound(
                (recv_win as f64 * crate::CONNECTION_WINDOW_FACTOR) as u64,
            );

            // When MAX_STREAM_DATA is sent, trigger MAX_DATA as well to avoid a
            // potential race condition.
            self.streams.rx_almost_full = true
        }

        // Create MAX_DATA frame if needed.
        if self.streams.need_send_max_data() {
            // Adjust the connection window size automatically.
            self.streams
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxData {
                max: self.streams.max_rx_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.rx_almost_full = false;
            // Apply the new flow control limit.
            self.streams.update_max_rx_data(now);
        }

        // Create STOP_SENDING frames if needed.
        for (stream_id, error_code) in self
            .streams
            .stopped()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StopSending {
                stream_id,
                error_code,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_stopped(stream_id, false, 0);
        }

        // Create RESET_STREAM frames if needed.
        for (stream_id, (error_code, final_size)) in self
            .streams
            .reset()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, (u64, u64))>>()
        {
            let frame = frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_reset(stream_id, false, 0, 0);
        }

        // Create STREAM_DATA_BLOCKED frames if needed.
        for (stream_id, limit) in self
            .streams
            .blocked()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StreamDataBlocked {
                stream_id,
                max: limit,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_blocked(stream_id, false, 0);
        }

        // Create STREAMS_BLOCKED frames if needed.
        for bidi in &[true, false] {
            if let Some(streams_blocked_at) = self.streams.streams_blocked_at(*bidi) {
                let frame = frame::Frame::StreamsBlocked {
                    bidi: *bidi,
                    max: streams_blocked_at,
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Clear the streams_blocked state.
                self.streams.update_streams_blocked_at(*bidi, None);
            }
        }

        Ok(())
    }

    /// Populate ConnectionClose frame to packet payload buffer.
    fn try_write_close_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // CONNECTION_CLOSE should be sent on the active path or the last available path.
        if !self.paths.get(path_id)?.active() && self.paths.len() > 1 {
            return Ok(());
        }

        if let Some(ref e) = self.local_error {
            let frame = if !e.is_app {
                Some(Frame::ConnectionClose {
                    error_code: e.error_code,
                    frame_type: 0,
                    reason: e.reason.clone(),
                })
            } else if pkt_type == PacketType::OneRTT || pkt_type == PacketType::ZeroRTT {
                // The application-specific variant of CONNECTION_CLOSE can
                // only be sent using 0-RTT or 1-RTT packets.
                // RFC 9000 Section 19.19
                Some(Frame::ApplicationClose {
                    error_code: e.error_code,
                    reason: e.reason.clone(),
                })
            } else {
                None
            };

            if let Some(frame) = frame {
                Connection::write_frame_to_packet(frame, out, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                let pto = self.paths.get(path_id)?.recovery.rtt.pto_base();
                let draining_timeout = time::Instant::now() + pto * 3;
                self.timers.set(Timer::Draining, draining_timeout);
            }
        }

        Ok(())
    }

    /// Populate Crypto frame to packet payload buffer.
    fn try_write_crypto_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // The CRYPTO frame is used to transmit cryptographic handshake messages
        // and can be sent in all packet types except 0-RTT.
        if pkt_type == PacketType::ZeroRTT {
            return Ok(());
        }

        let level = pkt_type.to_level()?;
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        let stream = crypto_streams.get_mut(level)?;
        let out = &mut out[st.written..];

        if !(stream.is_sendable()
            && out.len() > frame::MAX_CRYPTO_OVERHEAD
            && !self.is_closing()
            && self.paths.get(path_id)?.active())
        {
            return Ok(());
        }

        let crypto_off = stream.send.send_off();
        let frame_hdr_len = frame::crypto_header_wire_len(crypto_off);
        if out.len() <= frame_hdr_len {
            return Ok(());
        }

        let (frame_data_len, _) = stream.send.read(&mut out[frame_hdr_len..])?;
        frame::encode_crypto_header(crypto_off, frame_data_len as u64, out)?;
        st.written += frame_hdr_len + frame_data_len;
        st.frames.push(Frame::Crypto {
            offset: crypto_off,
            length: frame_data_len,
            data: Bytes::default(),
        });
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;

        Ok(())
    }

    /// Populate Stream frame to packet payload buffer.
    fn try_write_stream_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let out = &mut out[st.written..];
        if (pkt_type != PacketType::OneRTT && pkt_type != PacketType::ZeroRTT)
            || self.is_closing()
            || out.len() <= frame::MAX_STREAM_OVERHEAD
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        let mut len = 0;
        let mut cap: usize = out.len();

        while let Some(stream_id) = self.streams.peek_sendable() {
            let stream = match self.streams.get_mut(stream_id) {
                // We should not send frames for streams that were already stopped.
                Some(s) if !s.send.is_stopped() => s,
                _ => {
                    self.streams.remove_sendable();
                    continue;
                }
            };

            // Get the lowest offset of data to be sent.
            let stream_off = stream.send.send_off();

            // Encode stream frame, instead of create a `frame::Frame::Stream`,
            // encode the data into the packet buffer directly.
            //
            // 1. Reserve some space in the output buffer for writing
            // the frame header.
            // 2. Read the data from the stream's SendBuf.
            // 3. encode the frame header with the updated frame header segments.
            let frame_hdr_len = frame::stream_header_wire_len(stream_id, stream_off);

            // Read stream data and write into the packet buffer directly.
            let (frame_data_len, fin) = stream.send.read(&mut out[len + frame_hdr_len..])?;

            // Retain stream data if needed.
            let data = if self.flags.contains(EnableMultipath)
                && buffer_required(self.multipath_conf.multipath_algorithm)
            {
                let start = len + frame_hdr_len;
                Bytes::copy_from_slice(&out[start..start + frame_data_len])
            } else {
                Bytes::new()
            };

            frame::encode_stream_header(
                stream_id,
                stream_off,
                frame_data_len as u64,
                fin,
                &mut out[len..len + frame_hdr_len],
            )?;

            let frame_len = frame_hdr_len + frame_data_len;
            st.written += frame_len;
            len += frame_len;
            cap -= frame_len;

            st.ack_eliciting = true;
            st.in_flight = true;
            st.has_data = true;
            st.frames.push(Frame::Stream {
                stream_id,
                offset: stream_off,
                length: frame_data_len,
                fin,
                data,
            });

            // If the stream is no longer sendable, remove it from the queue
            if !stream.is_sendable() {
                self.streams.remove_sendable();
            }

            // If the buffer is too short, we won't attempt to write any more stream frames into it.
            if cap <= frame::MAX_STREAM_OVERHEAD {
                break;
            }
        }

        Ok(())
    }

    /// Populate NewToken frame to packet payload buffer.
    fn try_write_new_token_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !(pkt_type == PacketType::OneRTT
            && self.token.is_some()
            && !self.is_closing()
            && self.paths.get(path_id)?.active()
            && self.flags.contains(NeedSendNewToken))
        {
            return Ok(());
        }

        let frame = Frame::NewToken {
            token: self.token.clone().unwrap(), // always success
        };

        Connection::write_frame_to_packet(frame, out, st)?;
        st.ack_eliciting = true;
        st.in_flight = true;
        self.flags.remove(NeedSendNewToken);

        Ok(())
    }

    /// Populate buffered frame to packet payload buffer.
    fn try_write_buffered_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || out.len() - st.written <= frame::MAX_STREAM_OVERHEAD
            || !path.active()
        {
            return Ok(());
        }

        // Get buffered frames on the path.
        let space = self
            .spaces
            .get_mut(path.space_id)
            .ok_or(Error::InternalError)?;
        if space.buffered.is_empty() {
            return Ok(());
        }
        debug!(
            "{} try to write buffered frames: path_id={} frames={}",
            self.trace_id,
            path_id,
            space.buffered.len()
        );

        while let Some((frame, buffer_type)) = space.buffered.pop_front() {
            match frame {
                Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    data,
                } => {
                    let stream = match self.streams.get_mut(stream_id) {
                        Some(v) => v,
                        _ => continue,
                    };

                    // Check acked range and write the first non-acked subrange
                    let range = offset..offset + length as u64;
                    if let Some(r) = stream.send.filter_acked(range) {
                        let data_len = Self::write_buffered_stream_frame_to_packet(
                            stream_id,
                            r.start,
                            fin && r.end == offset + length as u64,
                            data.slice((r.start - offset) as usize..(r.end - offset) as usize),
                            out,
                            buffer_type,
                            st,
                        )?;

                        // Processing the following subrange.
                        if r.start + (data_len as u64) < offset + length as u64 {
                            let tail_len =
                                (offset + length as u64 - r.start - data_len as u64) as usize;
                            let frame = Frame::Stream {
                                stream_id,
                                offset: r.start + data_len as u64,
                                length: tail_len,
                                fin,
                                data: data.slice(length - tail_len..),
                            };
                            space.buffered.push_front(frame, buffer_type);
                        }

                        if data_len == 0 {
                            break;
                        }
                    }
                }

                // Ignore other buffered frames.
                _ => continue,
            }
        }

        Ok(())
    }

    fn write_buffered_stream_frame_to_packet(
        stream_id: u64,
        offset: u64,
        mut fin: bool,
        mut data: Bytes,
        out: &mut [u8],
        buffer_type: BufferType,
        st: &mut FrameWriteStatus,
    ) -> Result<usize> {
        let out = &mut out[st.written..];
        if out.len() <= frame::MAX_STREAM_OVERHEAD {
            return Ok(0);
        }

        let hdr_len = frame::stream_header_wire_len(stream_id, offset);
        let data_len = cmp::min(data.len(), out.len() - hdr_len);
        if data_len < data.len() {
            data.truncate(data_len);
            fin = false;
        }

        frame::encode_stream_header(stream_id, offset, data_len as u64, fin, out)?;
        out[hdr_len..hdr_len + data.len()].copy_from_slice(&data);

        st.written += hdr_len + data_len;
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;
        st.buffer_flags.mark(buffer_type);
        st.frames.push(Frame::Stream {
            stream_id,
            offset,
            length: data.len(),
            fin,
            data,
        });
        Ok(data_len)
    }

    /// Populate a QUIC frame to the give buffer.
    fn write_frame_to_packet(
        frame: Frame,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
    ) -> Result<()> {
        // Check whether there is enough room to write the frame.
        if st.written + frame.wire_len() > out.len() {
            return Err(Error::Done);
        }

        st.written += frame.to_bytes(&mut out[st.written..])?;
        st.frames.push(frame);
        Ok(())
    }

    /// Process lost frames in all packet number spaces and prepare for retransmitting
    ///
    /// QUIC packets that are determined to be lost are not retransmitted whole.
    /// The same applies to the frames that are contained within lost packets.
    /// Instead, the information that might be carried in frames is sent again
    /// in new frames as needed.
    /// See RFC 9000 Section 13.3
    fn process_all_lost_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for lost_frame in space.lost.drain(..) {
                match lost_frame {
                    // ACK frames carry the most recent set of acknowledgments and
                    // the acknowledgment delay from the largest acknowledged packet
                    Frame::Ack { .. } => {
                        space.need_send_ack = true;
                    }

                    // The HANDSHAKE_DONE frame MUST be retransmitted until it
                    // is acknowledged.
                    Frame::HandshakeDone if !self.flags.contains(HandshakeDoneAcked) => {
                        self.flags.insert(NeedSendHandshakeDone);
                    }

                    // New connection IDs are sent in NEW_CONNECTION_ID frames
                    // and retransmitted if the packet containing them is lost.
                    Frame::NewConnectionId { seq_num, .. } => {
                        self.cids.mark_scid_to_advertise(seq_num, true);
                    }

                    // Retired connection IDs are sent in RETIRE_CONNECTION_ID
                    // frames and retransmitted if the packet containing them is
                    // lost.
                    Frame::RetireConnectionId { seq_num } => {
                        self.cids.mark_dcid_to_retire(seq_num, true);
                    }

                    // NEW_TOKEN frames are retransmitted if the packet
                    // containing them is lost.
                    Frame::NewToken { .. } => {
                        self.flags.insert(NeedSendNewToken);
                    }

                    // Data sent in CRYPTO frames is retransmitted according to
                    // the rules in [QUIC-RECOVERY], until all data has been
                    // acknowledged.
                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.retransmit(offset, length);
                        }
                    }

                    // Application data sent in STREAM frames is retransmitted
                    // in new STREAM frames unless the endpoint has sent a
                    // RESET_STREAM for that stream.
                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        fin,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_lost(stream_id, offset, length, fin);
                    }

                    // Cancellation of stream transmission, as carried in a
                    // RESET_STREAM frame, is sent until acknowledged or until
                    // all stream data is acknowledged by the peer.
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .on_reset_stream_frame_lost(stream_id, error_code, final_size);
                    }

                    // An updated value is sent when the packet containing the
                    // most recent MAX_STREAM_DATA frame for a stream is lost.
                    Frame::MaxStreamData { stream_id, .. } => {
                        self.streams.on_max_stream_data_frame_lost(stream_id);
                    }

                    // An updated value is sent in a MAX_DATA frame if the packet
                    // containing the most recently sent MAX_DATA frame is
                    // declared lost.
                    Frame::MaxData { .. } => {
                        self.streams.on_max_data_frame_lost();
                    }

                    // Request that a peer cease transmission of data on a stream,
                    // as carried in a STOP_SENDING frame, is sent until acknowledged
                    // or until receive-side of the stream is finished.
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    } => {
                        self.streams
                            .on_stop_sending_frame_lost(stream_id, error_code);
                    }

                    // Request that a peer update its max_streams limit, is sent until
                    // acknowledged or receive MAX_STREAMS frame from peer.
                    Frame::StreamsBlocked { bidi, max } => {
                        self.streams.on_streams_blocked_frame_lost(bidi, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a stream scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::StreamDataBlocked { stream_id, max } => {
                        self.streams
                            .on_stream_data_blocked_frame_lost(stream_id, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a connection scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::DataBlocked { max } => {
                        self.streams.on_data_blocked_frame_lost(max);
                    }

                    // An updated value is sent when a packet containing the
                    // most recent MAX_STREAMS for a stream type frame is
                    // declared lost.
                    Frame::MaxStreams { bidi, max } => {
                        self.streams.on_max_streams_frame_lost(bidi, max);
                    }

                    // A PING frame contain no information, so lost PING frames
                    // do not require repair. However, if it indicates the loss
                    // of a PMTU probe, we will try to schedule a new probe.
                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_lost(probe_size, peer_mds);
                            debug!(
                                "{} lost MTU probe on path {:?} size={}",
                                self.trace_id, path, probe_size
                            );
                        }
                    }

                    _ => (),
                }
            }
        }
    }

    /// Select an available path for sending packet
    ///
    /// The selected path should have a packet that can be sent out, unless none
    /// of the paths are feasible.
    fn select_send_path(&mut self) -> Result<usize> {
        // Select an unvalidated path with path probing packets to send
        if self.is_established() {
            let mut probing = self
                .paths
                .iter_mut()
                .filter(|(_, p)| p.dcid_seq.is_some())
                .filter(|(_, p)| p.need_send_validation_frames())
                .map(|(pid, _)| pid);

            if let Some(pid) = probing.next() {
                return Ok(pid);
            }
        }

        // Multipath scheduling for Multipath QUIC
        if self.flags.contains(EnableMultipath) {
            // Select a validated path with sufficient congestion window by the
            // multipath scheduler.
            if self.need_send_path_unaware_frames() {
                let s = match self.multipath_scheduler {
                    Some(ref mut scheduler) => scheduler,
                    None => return Err(Error::InternalError),
                };
                if let Ok(pid) = s.on_select(&mut self.paths, &mut self.spaces, &mut self.streams) {
                    return Ok(pid);
                }
            }

            // Select a validated path with ACK/PTO/Buffered packets to send.
            for (pid, path) in self.paths.iter_mut() {
                if !path.active() {
                    continue;
                }
                match self.spaces.get(path.space_id) {
                    Some(space) => {
                        if !space.recv_pkt_num_need_ack.is_empty() && space.need_send_ack {
                            return Ok(pid);
                        }
                        if space.loss_probes > 0 {
                            return Ok(pid);
                        }
                        if space.need_send_buffered_frames() && path.recovery.can_send() {
                            return Ok(pid);
                        }
                        if path.need_send_ping {
                            return Ok(pid);
                        }
                        continue;
                    }
                    None => continue,
                }
            }
        }

        // Select the active path
        self.paths.get_active_path_id()
    }

    /// Select packet type for outgoing packets
    fn select_send_packet_type(&mut self, pid: usize) -> Result<PacketType> {
        // When sending a CONNECTION_CLOSE frame, the goal is to ensure that
        // the peer will process the frame. Generally, this means sending the
        // frame in a packet with the highest level of packet protection to
        // avoid the packet being discarded.
        // See RFC 9000 Section 10.2.3
        if self.local_error.as_ref().is_some_and(|e| !e.is_app) {
            let pkt_type = match self.tls_session.write_level() {
                Level::Initial => PacketType::Initial,
                Level::Handshake => PacketType::Handshake,
                Level::ZeroRTT => unreachable!(),
                Level::OneRTT => PacketType::OneRTT,
            };

            // However, prior to confirming the handshake, it is possible that
            // more advanced packet protection keys are not available to the peer.
            if !self.is_established() {
                match pkt_type {
                    PacketType::OneRTT => return Ok(PacketType::Handshake),

                    PacketType::Handshake
                        if self.tls_session.get_keys(Level::Initial).seal.is_some() =>
                    {
                        return Ok(PacketType::Initial);
                    }

                    _ => (),
                };
            }
            return Ok(pkt_type);
        }

        // Coalescing packets in order of increasing encryption levels
        // (Initial, 0-RTT, Handshake, 1-RTT) makes it more likely that the
        // receiver will be able to process all the packets in a single pass.
        let pkt_types = [
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRTT,
        ];
        for pkt_type in pkt_types.iter() {
            // Only send packets in a space when we have the send keys for it.
            let level = pkt_type.to_level()?;
            if self.tls_session.get_keys(level).seal.is_none() {
                continue;
            }

            // We are ready to send data for this packet number space.
            let mut crypto_streams = self.crypto_streams.borrow_mut();
            if crypto_streams.get_mut(level)?.is_sendable() {
                return Ok(*pkt_type);
            }

            // We are ready to send ack for this packet number space.
            let space_id = self.get_space_id(*pkt_type, pid)?;
            let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
            if space.need_send_ack {
                return Ok(*pkt_type);
            }

            // There are lost frames in this packet number space.
            if !space.lost.is_empty() {
                return Ok(*pkt_type);
            }

            // We need to send PTO probe packets.
            if space.loss_probes > 0 {
                return Ok(*pkt_type);
            }
        }

        // If there are sendable, reset, stopped, almost full, blocked streams,
        // or need to update concurrency limits, use the 0RTT/1RTT packet.
        let path = self.paths.get(pid)?;
        if (self.is_established()
            // Note: The server's use of 1-RTT keys before the handshake is
            // complete is limited to sending data. BoringSSL will provide 1-RTT
            // write secret until the handshake is complete.
            // See RFC 9001 Section 5.7
            || self.tls_session.get_keys(Level::OneRTT).seal.is_some()
            || self.tls_session.is_in_early_data())
            && (self.local_error.as_ref().is_some_and(|e| e.is_app)
                || path.need_send_validation_frames()
                || path.dplpmtud.should_probe()
                || path.need_send_ping
                || self.cids.need_send_cid_control_frames()
                || self.streams.need_send_stream_frames()
                || self.spaces.need_send_buffered_frames())
        {
            if self.tls_session.is_in_early_data() {
                return Ok(PacketType::ZeroRTT);
            }
            return Ok(PacketType::OneRTT);
        }

        Err(Error::Done)
    }

    /// Check whether there are any unsent frames that can be sent on any path.
    fn need_send_path_unaware_frames(&self) -> bool {
        self.local_error.as_ref().is_some_and(|e| e.is_app)
            || self.cids.need_send_cid_control_frames()
            || self.streams.need_send_stream_frames()
    }

    /// Find space id for the specified packet type and path id.
    fn get_space_id(&self, pkt_type: PacketType, path_id: usize) -> Result<SpaceId> {
        if !self.flags.contains(EnableMultipath) {
            return pkt_type.to_space();
        }

        if pkt_type != PacketType::OneRTT {
            return pkt_type.to_space();
        }

        match self.paths.get(path_id) {
            Ok(path) => Ok(path.space_id),
            Err(e) => Err(e),
        }
    }

    /// Select the path that the incoming packet belongs to, or creates a new
    /// one if no existing path matches.
    fn get_or_create_path(
        &mut self,
        recv_pid: Option<usize>,
        dcid: &ConnectionId,
        info: &PacketInfo,
        buf_len: usize,
    ) -> Result<usize> {
        // Note: If the incoming packet carrys an unknown dcid, just ignore and drop it.
        let (cid_seq, mut cid_pid) = self.cids.find_scid(dcid).ok_or(Error::Done)?;

        // The incoming packet arrived on the existing path (for Client/Server).
        if let Some(recv_pid) = recv_pid {
            let recv_path = self.paths.get_mut(recv_pid)?;
            let cid_item = recv_path.scid_seq.and_then(|v| self.cids.get_scid(v).ok());

            if cid_item.map(|c| &c.cid) != Some(dcid) {
                recv_path.scid_seq = Some(cid_seq);
                self.cids.mark_scid_used(cid_seq, recv_pid)?;
            }
            return Ok(recv_pid);
        }

        // The incoming packet arrived on a new path (for Server).
        if self.cids.zero_length_scid() {
            cid_pid = None;
        }
        let mut path = path::Path::new(
            info.dst,
            info.src,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );

        path.scid_seq = Some(cid_seq);
        path.initiate_path_chal();

        // Try to create a packet number space for the new path in MPQUIC mode.
        if self.flags.contains(EnableMultipath) {
            match cid_pid {
                None => {
                    // Found a new path initiated by client
                    let space_id = self.spaces.add();
                    path.space_id = space_id;
                }
                Some(cid_pid) => {
                    // Found NAT rebinding: If path migration occurs, the new path
                    // will simply share the same packet number space with the
                    // original path.
                    path.space_id = self.paths.get(cid_pid)?.space_id;
                }
            }
        }

        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);
        if cid_pid.is_none() {
            self.cids.mark_scid_used(cid_seq, pid)?;
        }
        Ok(pid)
    }

    /// Return the amount of time until the next timeout event.
    pub(crate) fn timeout(&mut self) -> Option<time::Duration> {
        if self.is_closed() {
            return None;
        }

        let time = if self.is_draining() {
            // Draining timer takes precedence over all other timers. If it is
            // set, it means the connection is in draining state and there's
            // need to process the other timers.
            self.timers.get(Timer::Draining)
        } else {
            // Use the lowest timer among all the other timers
            match self.paths.min_loss_detection_timer() {
                Some(time) => self.timers.set(Timer::LossDetection, time),
                None => self.timers.stop(Timer::LossDetection),
            }
            match self.paths.min_pacer_timer() {
                Some(time) => self.timers.set(Timer::Pacer, time),
                None => self.timers.stop(Timer::Pacer),
            }
            match self.paths.min_path_chal_timer() {
                Some(time) => self.timers.set(Timer::PathChallenge, time),
                None => self.timers.stop(Timer::PathChallenge),
            }
            match self.spaces.min_ack_timer() {
                Some(time) => self.timers.set(Timer::Ack, time),
                None => self.timers.stop(Timer::Ack),
            }

            self.timers.next_timeout()
        };

        // Calculate duration since now.
        let d = time.map(|v| {
            let now = time::Instant::now();
            if v <= now {
                time::Duration::ZERO
            } else {
                v.duration_since(now)
            }
        });
        trace!("{} next timeout duration {:?}", self.trace_id(), d);
        d
    }

    /// Process timeout event on the connection.
    pub(crate) fn on_timeout(&mut self, now: time::Instant) {
        for timer in Timer::iter() {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            trace!("{} timer {:?} timeout", self.trace_id, timer);

            let handshake_status = self.handshake_status();
            self.timers.stop(timer);
            match timer {
                Timer::LossDetection => {
                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.loss_detection_timer() {
                            if timer > now {
                                continue;
                            }
                            let (lost_pkts, lost_bytes) = path.recovery.on_loss_detection_timeout(
                                path.space_id,
                                &mut self.spaces,
                                handshake_status,
                                #[cfg(feature = "qlog")]
                                self.qlog.as_mut(),
                                now,
                            );
                            self.stats.lost_count += lost_pkts;
                            self.stats.lost_bytes += lost_bytes;

                            // Write RecoveryMetricsUpdate event to qlog.
                            #[cfg(feature = "qlog")]
                            if let Some(qlog) = &mut self.qlog {
                                path.recovery.qlog_recovery_metrics_updated(qlog);
                            }
                        }
                    }
                }

                Timer::Ack => {
                    for (_, space) in self.spaces.iter_mut() {
                        if let Some(timer) = space.ack_timer {
                            if timer > now {
                                continue;
                            }
                            debug!("{} ack timeout for space {:?}", self.trace_id, space.id);
                            space.need_send_ack = true;
                            space.ack_timer = None;
                        }
                    }
                }

                Timer::Pacer => {
                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.pacer_timer
                            && timer > now
                        {
                            continue;
                        }
                        path.recovery.pacer_timer = None;
                    }
                    self.mark_tickable(true);
                }

                Timer::Idle => {
                    info!("{} idle timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(IdleTimeout);
                }

                Timer::Draining => self.flags.insert(Closed),

                Timer::KeyDiscard => self.tls_session.discard_prev_key(),

                Timer::KeepAlive => (), // TODO: schedule an outgoing Ping

                Timer::PathChallenge => self.paths.on_path_chal_timeout(now),

                Timer::Handshake => {
                    info!("{} handshake timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(HandshakeTimeout);
                }
            }
        }
    }

    /// Return the idle timeout of the connection.
    fn idle_timeout(&mut self) -> Option<time::Duration> {
        // The idle timeout is disabled.
        if self.local_transport_params.max_idle_timeout == 0
            && self.peer_transport_params.max_idle_timeout == 0
        {
            return None;
        }

        // The effective value at an endpoint is computed as the minimum of
        // the two advertised values.
        let idle_timeout = if self.local_transport_params.max_idle_timeout == 0 {
            self.peer_transport_params.max_idle_timeout
        } else if self.peer_transport_params.max_idle_timeout == 0 {
            self.local_transport_params.max_idle_timeout
        } else {
            cmp::min(
                self.local_transport_params.max_idle_timeout,
                self.peer_transport_params.max_idle_timeout,
            )
        };
        let idle_timeout = time::Duration::from_millis(idle_timeout);

        // To avoid excessively small idle timeout periods, endpoints MUST
        // increase the idle timeout period to be at least three times the
        // current Probe Timeout (PTO).
        // See RFC 9000 Section 10.1
        let path_pto = match self.paths.get_active_mut() {
            Ok(p) => p.recovery.rtt.pto_base(),
            Err(_) => time::Duration::ZERO,
        };
        let idle_timeout = cmp::max(idle_timeout, 3 * path_pto);

        Some(idle_timeout)
    }

    /// Whether encryption on the specified packet type should be disabled
    fn is_encryption_disabled(&self, pkt_type: PacketType) -> bool {
        pkt_type == PacketType::OneRTT && self.flags.contains(DisableEncryption)
    }

    /// Check whether the connection handshake is complete.
    pub fn is_established(&self) -> bool {
        self.flags.contains(HandshakeCompleted)
    }

    /// Check whether the connection handshake is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.flags.contains(HandshakeConfirmed)
    }

    /// Check whether the connection is resumed.
    pub fn is_resumed(&self) -> bool {
        self.tls_session.is_resumed()
    }

    /// Check whether the connection has a pending handshake that has progressed
    /// enough to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.tls_session.is_in_early_data()
    }

    /// Check whether the multipath have been negotiated.
    pub fn is_multipath(&self) -> bool {
        self.flags.contains(EnableMultipath)
    }

    /// Return the negotiated application level protocol.
    pub fn application_proto(&self) -> &[u8] {
        self.tls_session.alpn_protocol()
    }

    /// Return the server name in the TLS SNI extension.
    pub fn server_name(&self) -> Option<&str> {
        self.tls_session.server_name()
    }

    /// Return the session data used by resumption.
    pub fn session(&self) -> Option<&[u8]> {
        self.tls_session.session()
    }

    /// Return details why 0-RTT was accepted or rejected.
    pub fn early_data_reason(&self) -> tls::SslEarlyDataReason {
        self.tls_session.early_data_reason()
    }

    /// Return a string representation for reason why 0-RTT was accepted or rejected.
    pub fn early_data_reason_string(&self) -> Result<Option<&str>> {
        self.tls_session.early_data_reason_string()
    }

    /// Check whether the connection is draining.
    ///
    /// If true, the connection object can not yet be dropped, but no data can
    /// be sent or received.
    pub fn is_draining(&self) -> bool {
        self.timers.get(Timer::Draining).is_some()
    }

    /// Check whether the connection is closing.
    pub fn is_closing(&self) -> bool {
        self.local_error.is_some()
    }

    /// Check whether the connection is closed.
    ///
    /// If true, the connection object can be dropped.
    pub fn is_closed(&self) -> bool {
        self.flags.contains(Closed)
    }

    /// Check whether the connection was closed due to idle timeout.
    pub fn is_idle_timeout(&self) -> bool {
        self.flags.contains(IdleTimeout)
    }

    /// Check whether the connection was closed due to handshake timeout.
    pub fn is_handshake_timeout(&self) -> bool {
        self.flags.contains(HandshakeTimeout)
    }

    /// Check whether the connection was closed due to stateless reset.
    pub fn is_reset(&self) -> bool {
        self.flags.contains(GotReset)
    }

    /// Close the connection.
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            return Err(Error::Done);
        }

        self.local_error = Some(ConnectionError {
            is_app: app,
            error_code: err,
            frame: None,
            reason: reason.to_vec(),
        });
        self.mark_tickable(true);
        Ok(())
    }

    /// Mark the connection as stateless reset by the peer.
    pub(crate) fn reset(&mut self) {
        if self.is_closed() || self.is_draining() {
            return;
        }

        // The connection is reset by the peer and it MUST enter the draining
        // period and not send any further packets on this connection.
        self.flags.insert(GotReset);
        if let Ok(p) = self.paths.get_active_mut() {
            let pto = p.recovery.rtt.pto_base();
            let now = time::Instant::now();
            self.timers.set(Timer::Draining, now + pto * 3);
        }
    }

    /// Returns the error from the peer, if any.
    pub fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// Returns the local error, if any.
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// Return statistics about the connection.
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Discard packet number space and related secrets.
    ///
    /// After QUIC has completed a move to a new encryption level, packet
    /// protection keys for previous encryption levels can be discarded.
    /// This occurs several times during the handshake, as well as when keys
    /// are updated.
    /// See RFC 9001 Section 4.9
    fn drop_space_state(&mut self, sid: SpaceId, now: time::Instant) {
        let level = match sid {
            SpaceId::Initial => Level::Initial,
            SpaceId::Handshake => Level::Handshake,
            _ => return,
        };

        // Discard unused keys for given level
        if self.tls_session.get_keys(level).open.is_none() {
            return;
        }
        self.tls_session.drop_keys(level);
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        crypto_streams.clear(level);

        // When Initial and Handshake packet protection keys are discarded, all
        // packets that were sent with those keys can no longer be acknowledged
        // because their acknowledgments cannot be processed.
        // The sender MUST discard all recovery state associated with those
        // packets and MUST remove them from the count of bytes in flight.
        let handshake_status = self.handshake_status();
        if let Ok(path) = self.paths.get_active_mut() {
            path.recovery
                .on_pkt_num_space_discarded(sid, &mut self.spaces, handshake_status, now);
        }
    }

    /// Return the handshake status
    fn handshake_status(&self) -> HandshakeStatus {
        let keys = self.tls_session.get_keys(Level::Handshake);

        HandshakeStatus {
            derived_handshake_keys: keys.seal.is_some() && keys.open.is_some(),
            peer_verified_address: self.flags.contains(PeerVerifiedInitialAddress),
            completed: self.is_established(),
        }
    }

    /// Return scid of the active path
    pub fn scid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .scid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_scid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over source ConnectionIdItem
    pub fn scid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.scid_iter()
    }

    /// Provide additional source CID and trigger sending NEW_CONNECTION_ID
    /// frames.
    pub(crate) fn add_scid(
        &mut self,
        scid: ConnectionId,
        reset_token: u128,
        retire_if_needed: bool,
    ) -> Result<u64> {
        self.cids
            .add_scid(scid, Some(reset_token), true, None, retire_if_needed)
    }

    /// Return true if the source CID is zero length
    pub fn zero_length_scid(&self) -> bool {
        self.cids.zero_length_scid()
    }

    /// Return dcid of the active path
    pub fn dcid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_dcid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over destination ConnectionIdItem
    pub fn dcid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.dcid_iter()
    }

    /// Return true if the destination CID is zero length
    pub fn zero_length_dcid(&self) -> bool {
        self.cids.zero_length_dcid()
    }

    /// Return original destination cid
    pub(crate) fn odcid(&self) -> Option<ConnectionId> {
        self.odcid
    }

    /// Return the unique trace id.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Set dcid provided by peer
    fn try_set_dcid_for_initial_path(&mut self, pid: usize, hdr: &PacketHeader) -> Result<()> {
        if self.flags.contains(GotPeerCid) {
            return Ok(());
        }

        if self.odcid.is_none() {
            self.odcid = Some(self.dcid()?);
        }
        self.set_initial_dcid(
            hdr.scid,
            self.peer_transport_params.stateless_reset_token,
            pid,
        )?;

        self.flags.insert(GotPeerCid);
        Ok(())
    }

    /// Set dcid for initial path of the connection
    fn set_initial_dcid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<u128>,
        path_id: usize,
    ) -> Result<()> {
        self.cids.set_initial_dcid(cid, reset_token, Some(path_id));
        self.paths.get_mut(path_id)?.dcid_seq = Some(0);

        Ok(())
    }

    /// Configure tls session to send transport parameters in the
    /// quic_transport_parameters extension in either the ClientHello or
    /// EncryptedExtensions handshake message.
    fn set_transport_params(&mut self) -> Result<()> {
        let mut raw_params = [0; 256];

        // Ensure desired wire values regardless of global defaults.
        let tp = self.local_transport_params.clone();

        let len = TransportParams::encode(&tp, &mut raw_params)?;
        self.tls_session.set_transport_params(&raw_params[..len])?;

        Ok(())
    }

    /// Return a func for writing crypto data from the TLS session to the crypto stream.
    fn get_write_method(&mut self) -> tls::WriteMethod {
        let crypto_streams = self.crypto_streams.clone();
        Box::new(move |level, data| {
            let mut crypto_streams = crypto_streams.borrow_mut();
            let stream = crypto_streams.get_mut(level)?;
            stream.send.write(Bytes::copy_from_slice(data), false)?;
            Ok(())
        })
    }

    /// Send a Ping frame for keep-alive.
    ///
    /// If `path_addr` is `None`, a Ping frame will be sent on each active path.
    /// Otherwise, a Ping frame will be on the specified path.
    pub fn ping(&mut self, path_addr: Option<FourTuple>) -> Result<()> {
        self.paths.mark_ping(path_addr)
    }

    /// Client add a new path on the connection.
    pub fn add_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<u64> {
        if !self.flags.contains(HandshakeCompleted) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        if self.paths.get_path_id(&(local_addr, remote_addr)).is_some() {
            return Err(Error::Done);
        }

        let dcid_seq = if self.cids.zero_length_dcid() {
            Some(0)
        } else {
            self.cids.lowest_unused_dcid_seq()
        };

        let mut path = path::Path::new(
            local_addr,
            remote_addr,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );
        path.dcid_seq = dcid_seq;
        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);

        if let Some(dcid_seq) = dcid_seq {
            self.cids.mark_dcid_used(dcid_seq, pid)?;
        }

        let path = self.paths.get_mut(pid)?;
        path.initiate_path_chal();

        // Create packet number space for the path when Multipath QUIC is enabled.
        if self.flags.contains(EnableMultipath) {
            let space_id = self.spaces.add();
            path.space_id = space_id;
        }

        self.mark_tickable(true);
        Ok(pid as u64)
    }

    /// Abandon a path for a Multipath QUIC connection.
    #[doc(hidden)]
    pub fn abandon_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        let pid = match self.paths.get_path_id(&(local_addr, remote_addr)) {
            Some(pid) => pid,
            None => return Ok(()),
        };

        // TODO: check number of active path

        // Mark the path as abandoned.
        let path = self.paths.get_mut(pid)?;
        path.is_abandon = true;
        Ok(())
    }

    /// Return an immutable reference to the specified path
    pub fn get_path(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&path::Path> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        self.paths.get(pid)
    }

    /// Return an immutable reference to the active path
    pub fn get_active_path(&self) -> Result<&path::Path> {
        self.paths.get_active()
    }

    /// Return an mutable reference to the specified path
    pub fn get_path_stats(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&crate::PathStats> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        Ok(self.paths.get_mut(pid)?.stats())
    }

    /// Migrates the connection to the specified path.
    #[doc(hidden)]
    pub fn migrate_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        // TODO: support migration
        Err(Error::InternalError)
    }

    /// Return an iterator over path addresses.
    pub fn paths_iter(&self) -> FourTupleIter {
        // Instead of trying to identify whether packets will be sent on the
        // given 4-tuple, simply filter paths that cannot be used.
        FourTupleIter {
            addrs: self
                .paths
                .iter()
                .map(|(_, p)| FourTuple {
                    local: p.local_addr(),
                    remote: p.remote_addr(),
                })
                .collect(),
        }
    }

    /// Return an iterator over streams that have data to read or an error to collect.
    pub fn stream_readable_iter(&self) -> StreamIter {
        self.streams.readable_iter()
    }

    /// Return an iterator over streams that can be written
    pub fn stream_writable_iter(&self) -> StreamIter {
        self.streams.writable_iter()
    }

    /// Return an iterator over all the existing streams on the connection.
    pub fn stream_iter(&self) -> StreamIter {
        self.streams.iter()
    }

    /// Return true if the stream has enough flow control capacity to send data
    /// and application wants to send more data.
    pub(crate) fn stream_check_writable(&self, stream_id: u64) -> bool {
        self.streams.check_writable(stream_id)
    }

    /// Return true if application wants to read more data from the stream.
    pub(crate) fn stream_check_readable(&self, stream_id: u64) -> bool {
        self.streams.check_readable(stream_id)
    }

    /// Set want write flag for a stream.
    pub fn stream_want_write(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_write(stream_id, want)
    }

    /// Set want read flag for a stream.
    pub fn stream_want_read(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_read(stream_id, want)
    }

    /// Read data from a stream
    pub fn stream_read(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        self.mark_tickable(true);
        let read_off = self.streams.stream_read_offset(stream_id);

        match self.streams.stream_read(stream_id, out) {
            Ok((read, fin)) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_read(qlog, stream_id, read_off.unwrap_or(0), read);
                }

                Ok((read, fin))
            }
            Err(e) => Err(e),
        }
    }

    /// Write data to a stream.
    pub fn stream_write(&mut self, stream_id: u64, buf: Bytes, fin: bool) -> Result<usize> {
        self.mark_tickable(true);
        let write_off = self.streams.stream_write_offset(stream_id);

        match self.streams.stream_write(stream_id, buf, fin) {
            Ok(written) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_write(
                        qlog,
                        stream_id,
                        write_off.unwrap_or(0),
                        written,
                    );
                }
                Ok(written)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a new stream with given stream id and priority.
    /// This is a low-level API for stream creation. It is recommended to use
    /// `stream_bidi_new` for bidirectional streams or `stream_uni_new` for
    /// undirectional streams.
    pub fn stream_new(&mut self, stream_id: u64, urgency: u8, incremental: bool) -> Result<()> {
        self.stream_set_priority(stream_id, urgency, incremental)
    }

    /// Create a new bidirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_bidi_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_bidi_new(urgency, incremental)
    }

    /// Create a new undirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_uni_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_uni_new(urgency, incremental)
    }

    /// Shutdown stream reading or writing.
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        self.mark_tickable(true);
        self.streams.stream_shutdown(stream_id, direction, err)
    }

    /// Set priority for a stream.
    pub fn stream_set_priority(
        &mut self,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) -> Result<()> {
        self.mark_tickable(true);
        self.streams
            .stream_set_priority(stream_id, urgency, incremental)
    }

    /// Return the stream's send capacity in bytes.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        self.streams.stream_capacity(stream_id)
    }

    /// Return true if the stream has enough send capacity.
    pub fn stream_writable(&mut self, stream_id: u64, len: usize) -> Result<bool> {
        self.streams.stream_writable(stream_id, len)
    }

    /// Return true if the stream has data to be read or an error to be collected.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        self.streams.stream_readable(stream_id)
    }

    /// Return true if the stream's receive-side final size is known,
    /// and the application has read all data from the stream.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.streams.stream_finished(stream_id)
    }

    /// Set user context for a stream.
    pub fn stream_set_context<T: Any + Send + Sync>(
        &mut self,
        stream_id: u64,
        ctx: T,
    ) -> Result<()> {
        self.streams.stream_set_context(stream_id, ctx)
    }

    /// Return the stream's user context.
    pub fn stream_context(&mut self, stream_id: u64) -> Option<&mut dyn Any> {
        self.streams.stream_context(stream_id)
    }

    /// Return immutable reference to streams
    pub(crate) fn get_streams(&self) -> &stream::StreamMap {
        &self.streams
    }

    /// Destroy the closed stream. It's only used by the Endpoint.
    pub(crate) fn stream_destroy(&mut self, stream_id: u64) {
        self.streams.stream_destroy(stream_id);
    }

    /// Return the internal identifier of the connection on the Endpoint. The
    /// internal identifier is not the same as the Connection ID as described
    /// in RFC 9000.
    pub fn index(&self) -> Option<u64> {
        self.index
    }

    /// Set the connection index on the Endpoint. It also enable generating
    /// endpoint-facing events.
    pub(crate) fn set_index(&mut self, v: u64) {
        self.index = Some(v);
        self.events.enable();
        self.streams.events.enable();
    }

    /// Set the queues shared by the endpoint and the connection.
    pub(crate) fn set_queues(&mut self, queues: Rc<RefCell<ConnectionQueues>>) {
        self.queues = Some(queues);
    }

    /// Client start handshake.
    pub(crate) fn start_handshake(&mut self) -> Result<()> {
        match self.tls_session.process() {
            Ok(_) => Ok(()),
            Err(Error::Done) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return an endpoint-facing event.
    pub(crate) fn poll(&mut self) -> Option<Event> {
        if let Some(event) = self.events.poll() {
            return Some(event);
        }
        if let Some(event) = self.streams.events.poll() {
            return Some(event);
        }
        None
    }

    /// Check whether internal events should be processed.
    pub(crate) fn is_ready(&mut self) -> bool {
        !self.events.is_empty()
            || !self.streams.events.is_empty()
            || self.streams.has_readable()
            || self.streams.has_writable()
            || self.is_closed()
    }

    /// Check whether the connection is tickable (i.e. on the tickable queue
    /// of the endpoint)
    pub(crate) fn is_tickable(&self) -> bool {
        self.flags.contains(Tickable)
    }

    /// Mark the connection as tickable.
    pub(crate) fn mark_tickable(&mut self, tickable: bool) {
        if tickable == self.is_tickable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if tickable {
                queues.tickable.insert(idx);
                self.flags.insert(Tickable);
            } else {
                queues.tickable.remove(&idx);
                self.flags.remove(Tickable);
            }
            trace!("{} marked tickable {}", self.trace_id, tickable);
        }
    }

    /// Check whether the connection is sendable (i.e. on the sendable queue
    /// of the endpoint)
    pub(crate) fn is_sendable(&self) -> bool {
        self.flags.contains(Sendable)
    }

    /// Mark the connection as sendable.
    pub(crate) fn mark_sendable(&mut self, sendable: bool) {
        if sendable == self.is_sendable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if sendable {
                queues.sendable.insert(idx);
                self.flags.insert(Sendable);
            } else {
                queues.sendable.remove(&idx);
                self.flags.remove(Sendable);
            }
            trace!("{} marked sendable {}", self.trace_id, sendable);
        }
    }

    /// Get user context for the connection.
    pub fn context(&mut self) -> Option<&mut dyn Any> {
        match self.context {
            Some(ref mut data) => Some(data.as_mut()),
            None => None,
        }
    }

    /// Set user context for the connection.
    pub fn set_context<T: Any + Send + Sync>(&mut self, data: T) {
        self.context = Some(Box::new(data))
    }

    /// Write a QuicParametersSet event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_params_set(
        qlog: &mut qlog::QlogWriter,
        params: &TransportParams,
        owner: events::Owner,
        cipher: Option<tls::Algorithm>,
    ) {
        let ev_data = params.to_qlog(owner, cipher);
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketReceived event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_packet_received(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let ev_data = events::EventData::QuicPacketReceived {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            trigger: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketSent event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_packet_sent(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let now = time::Instant::now();

        let ev_data = events::EventData::QuicPacketSent {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };
        qlog.add_event_data(now, ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_quic_data_acked(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        offset: u64,
        length: usize,
    ) {
        let ev_data = events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(offset),
            length: Some(length as u64),
            from: Some(events::DataRecipient::Transport),
            to: Some(events::DataRecipient::Dropped),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_transport_data_read(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        read_off: u64,
        read: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(read_off),
            length: Some(read as u64),
            from: Some(qlog::events::DataRecipient::Transport),
            to: Some(qlog::events::DataRecipient::Application),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    fn qlog_transport_data_write(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        write_off: u64,
        written: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(write_off),
            length: Some(written as u64),
            from: Some(qlog::events::DataRecipient::Application),
            to: Some(qlog::events::DataRecipient::Transport),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }
}

/// A set of crypto streams for Initial/Handshake/1RTT level.
struct CryptoStreams {
    streams: [Stream; 3],
}

impl CryptoStreams {
    /// Create crypto streams for Initial/Handshake/1RTT level.
    pub fn new() -> Self {
        CryptoStreams {
            streams: [
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
            ],
        }
    }

    /// Get crypto stream for the given encryption level.
    pub fn get_mut(&mut self, level: Level) -> Result<&mut Stream> {
        match level {
            Level::Initial => Ok(&mut self.streams[0]),
            Level::Handshake => Ok(&mut self.streams[1]),
            Level::OneRTT => Ok(&mut self.streams[2]),
            _ => Err(Error::InternalError),
        }
    }

    /// Clear a crypto stream when dropping the corresponding keys.
    pub fn clear(&mut self, level: Level) {
        match level {
            Level::Initial => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            Level::Handshake => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            _ => (),
        }
    }

    /// Create a crypto stream.
    ///
    /// Data sent in CRYPTO frames is not flow controlled in the same way as
    /// stream data. QUIC relies on the implementation to avoid excessive
    /// buffering of data
    fn new_stream() -> Stream {
        Stream::new(true, true, u64::MAX, u64::MAX, stream::MAX_STREAM_WINDOW)
    }
}

/// Collection of packets which were received before decryption keys are available.
struct UndecryptablePackets {
    zerortt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    handshake_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    onertt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    capacity: usize,
}

impl UndecryptablePackets {
    fn new(capacity: usize) -> Self {
        Self {
            zerortt_pkts: VecDeque::with_capacity(capacity),
            handshake_pkts: VecDeque::with_capacity(capacity),
            onertt_pkts: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, pkt_type: &PacketType, pkt: Vec<u8>, info: &PacketInfo) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => {
                if self.zerortt_pkts.len() > self.capacity {
                    false
                } else {
                    self.zerortt_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::Handshake => {
                if self.handshake_pkts.len() > self.capacity {
                    false
                } else {
                    self.handshake_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::OneRTT => {
                if self.onertt_pkts.len() > self.capacity {
                    false
                } else {
                    self.onertt_pkts.push_back((pkt, *info));
                    true
                }
            }
            _ => false,
        }
    }

    fn pop(&mut self, pkt_type: &PacketType) -> Option<(Vec<u8>, PacketInfo)> {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.pop_front(),
            PacketType::Handshake => self.handshake_pkts.pop_front(),
            PacketType::OneRTT => self.onertt_pkts.pop_front(),
            _ => None,
        }
    }

    fn is_empty(&self, pkt_type: &PacketType) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.is_empty(),
            PacketType::Handshake => self.handshake_pkts.is_empty(),
            PacketType::OneRTT => self.onertt_pkts.is_empty(),
            _ => true,
        }
    }

    fn all_empty(&self) -> bool {
        self.zerortt_pkts.is_empty()
            && self.handshake_pkts.is_empty()
            && self.onertt_pkts.is_empty()
    }
}

/// Various flags of QUIC connection
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy)]
enum ConnectionFlags {
    /// The version negotiation has been performed.
    DidVersionNegotiation = 1 << 0,

    /// The stateless retry has been performed.
    DidRetry = 1 << 1,

    /// The initial secrets have been derived.
    DerivedInitialSecrets = 1 << 2,

    /// The client's session has been started to handshake.
    InitiatedClientHandshake = 1 << 3,

    /// The peer's cid has been saved.
    GotPeerCid = 1 << 4,

    /// The peer's transport parameters have been processed.
    AppliedPeerTransportParams = 1 << 5,

    /// The peer has verified local initial address.
    PeerVerifiedInitialAddress = 1 << 6,

    /// The handshake has been completed.
    HandshakeCompleted = 1 << 7,

    /// The connection has been confirmed.
    HandshakeConfirmed = 1 << 8,

    /// The connection has been closed.
    Closed = 1 << 9,

    /// The connection was closed due to the idle timeout.
    IdleTimeout = 1 << 10,

    /// The connection was closed due to handshake timeout.
    HandshakeTimeout = 1 << 11,

    /// The connection was closed due to stateless reset.
    GotReset = 1 << 12,

    /// An ack-eliciting packet should be sent.
    NeedSendAckEliciting = 1 << 13,

    /// A NewToken frame should be sent.
    NeedSendNewToken = 1 << 14,

    /// A HandshakeDone frame should be sent.
    NeedSendHandshakeDone = 1 << 15,

    /// The client has acknowledged the server's HandshakeDone.
    HandshakeDoneAcked = 1 << 16,

    /// The connection has sent an ack-eliciting packet since receiving a packet.
    /// It is used for resetting Idle timer.
    SentAckElicitingSinceRecvPkt = 1 << 17,

    /// The connection is in the tickable queue of the endpoint.
    Tickable = 1 << 18,

    /// The connection is in the sendable queue of the endpoint.
    Sendable = 1 << 19,

    /// The multipath extension is successfully negotiated.
    EnableMultipath = 1 << 20,

    /// The disable_1rtt_encryption is successfully negotiated.
    DisableEncryption = 1 << 21,
}

/// Statistics about a QUIC connection.
#[repr(C)]
#[derive(Default)]
pub struct ConnectionStats {
    /// Total number of received packets.
    pub recv_count: u64,

    /// Total number of bytes received on the connection.
    pub recv_bytes: u64,

    /// Total number of sent packets.
    pub sent_count: u64,

    /// Total number of bytes sent on the connection.
    pub sent_bytes: u64,

    /// Total number of lost packets.
    pub lost_count: u64,

    /// Total number of bytes lost on the connection.
    pub lost_bytes: u64,
}

/// FrameWriteStatus is used to collect various states during writing frames
/// to a QUIC packet.
#[derive(Clone, Debug, Default)]
struct FrameWriteStatus {
    /// Number of bytes written to the packet payload
    written: usize,

    /// Frames written to the packet payload
    frames: Vec<Frame>,

    /// Whether it contains frames other than ACK, PADDING, and CONNECTION_CLOSE
    ack_eliciting: bool,

    /// Whether it is an in-flight packet (ack-eliciting packet or contain a
    /// PADDING frame)
    in_flight: bool,

    /// Whether it contains CRYPTO or STREAM frame
    has_data: bool,

    /// Whether it contains a PATH_CHALLENGE frame
    challenge: Option<[u8; 8]>,

    /// Whether a PING frame should be added to elicit an ACK from the peer.
    ack_elicit_required: bool,

    /// Whether the congestion window should be ignored.
    is_probe: bool,

    /// Whether it is a PMTU probe packet
    is_pmtu_probe: bool,

    /// Whether it consumes the pacer's tokens
    pacing: bool,

    /// Packet overhead (i.e. packet header and crypto overhead) in bytes
    overhead: usize,

    /// Status about buffered frames written to the packet.
    buffer_flags: BufferFlags,
}

/// Handshake status for loss recovery
#[derive(Clone, Copy, Debug)]
struct HandshakeStatus {
    /// Whether the Handshake keys have been derived.
    derived_handshake_keys: bool,

    /// Whether the peer has verified local initial address.
    peer_verified_address: bool,

    /// whether the connection handshake is complete.
    completed: bool,
}

mod cid;
mod flowcontrol;
pub mod path;
mod pmtu;
mod recovery;
pub(crate) mod rtt;
pub(crate) mod space;
pub(crate) mod stream;
pub(crate) mod timer;
