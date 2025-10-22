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

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use crate::ConnectionId;
use crate::MAX_STREAMS_PER_TYPE;
use crate::Result;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::Error;
#[cfg(feature = "qlog")]
use crate::qlog;
#[cfg(feature = "qlog")]
use crate::qlog::events::EventData;
use crate::tls;
use crate::token::ResetToken;
use rand::RngCore;

fn generate_grease_tp() -> (u64, Vec<u8>) {
    // Known parameter IDs to avoid colliding with
    const KNOWN_IDS: &[u64] = &[
        0x0000,
        0x0001,
        0x0002,
        0x0003,
        0x0004,
        0x0005,
        0x0006,
        0x0007,
        0x0008,
        0x0009,
        0x000a,
        0x000b,
        0x000c,
        0x000d,
        0x000e,
        0x000f,
        0x0010,
        0x0011,
        0x0020,
        0x4752,
        0x3127,
        0xbaad,
        0x0f739bbc1b666d05,
    ];

    // Generate GREASE TP id of the form 31*n + 27 (common GREASE pattern in QUIC codepoints)
    // within the 62-bit varint space.
    let mut rid;
    loop {
        let n = (rand::rng().next_u64() & 0x3fff_ffff_ffff_fff0) / 31; // spread n
        rid = n.saturating_mul(31).saturating_add(27);
        rid &= 0x3fff_ffff_ffff_ffff; // ensure 62-bit
        if rid > 0x20 && !KNOWN_IDS.contains(&rid) {
            break;
        }
    }

    // Prefer small GREASE value lengths like Chrome (0..4 bytes).
    let len = (rand::rng().next_u32() % 5) as usize;
    let mut val = vec![0u8; len];
    rand::rng().fill_bytes(&mut val);
    (rid, val)
}

/// TransportParams is a sequence of transport parameters.
///
/// These parameters are carried in a TLS extension for integrity protection.
/// See RFC 9000 Section 18
#[derive(Clone, Debug, PartialEq)]
pub struct TransportParams {
    /// The value of the Destination Connection ID field from the first
    /// Initial packet sent by the client; This transport parameter is only
    /// sent by a server.
    pub original_destination_connection_id: Option<ConnectionId>,

    /// The maximum idle timeout is a value in milliseconds that is encoded
    /// as an integer.
    pub max_idle_timeout: u64,

    /// A stateless reset token is used in verifying a stateless reset;
    /// This parameter is a sequence of 16 bytes and may be sent by a server.
    pub stateless_reset_token: Option<u128>,

    /// The parameter is an integer value that limits the size of UDP payloads
    /// that the endpoint is willing to receive.
    pub max_udp_payload_size: u64,

    /// The parameter is an integer value that contains the initial value for
    /// the maximum amount of data that can be sent on the connection.
    pub initial_max_data: u64,

    /// This parameter is an integer value specifying the initial flow control
    /// limit for locally initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,

    /// This parameter is an integer value specifying the initial flow control
    /// limit for peer-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,

    /// This parameter is an integer value specifying the initial flow control
    /// limit for unidirectional streams.
    pub initial_max_stream_data_uni: u64,

    /// The parameter is an integer value that contains the initial maximum
    /// number of bidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate.
    pub initial_max_streams_bidi: u64,

    /// The parameter is an integer value that contains the initial maximum
    /// number of unidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate.
    pub initial_max_streams_uni: u64,

    /// The parameter is an integer value indicating an exponent used to
    /// decode the ACK Delay field in the ACK frame
    pub ack_delay_exponent: u64,

    /// The parameter is an integer value indicating the maximum amount of time
    /// in milliseconds by which the endpoint will delay sending acknowledgments.
    pub max_ack_delay: u64,

    /// The parameter is included if the endpoint does not support active
    /// connection migration on the address being used during the handshake.
    pub disable_active_migration: bool,

    /// The server's preferred address is used to effect a change in server
    /// address at the end of the handshake; This transport parameter is only
    /// sent by a server.
    pub preferred_address: Option<PreferredAddress>,

    /// The parameter is an integer value specifying the maximum number of
    /// connection IDs from the peer that an endpoint is willing to store.
    pub active_conn_id_limit: u64,

    /// The parameter is the value that the endpoint included in the Source
    /// Connection ID field of the first Initial packet it sends for the connection;
    pub initial_source_connection_id: Option<ConnectionId>,

    /// The parameter is the value that the server included in the Source
    /// Connection ID field of a Retry packet; This transport parameter is only
    /// sent by a server.
    pub retry_source_connection_id: Option<ConnectionId>,

    /// The parameter is included if the endpoint supports the multipath extension.
    /// This parameter has a zero-length value.
    /// See draft-ietf-quic-multipath-05.
    pub enable_multipath: bool,

    /// The parameter is used to negotiate the disablement of encryption on 1-RTT
    /// packets. It is only meant to be used in environments where both endpoints
    /// completely trust the path between themselves.
    /// See draft-banks-quic-disable-encryption-00.
    pub disable_encryption: bool,

    /// QUIC DATAGRAM extension: maximum datagram frame size supported.
    /// See RFC 9221. A value of 0 indicates not supported.
    pub max_datagram_frame_size: u64,

    /// Version Information transport parameter (draft-ietf-quic-version-negotiation).
    /// Contains the chosen version and a list of other supported versions.
    pub version_information: Option<VersionInformation>,

    /// Google-specific transport parameter carrying QUIC version (0x4752).
    pub google_quic_version: Option<u32>,

    /// Google-specific transport parameter for Initial RTT in microseconds (0x3127).
    pub google_initial_rtt: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VersionInformation {
    pub chosen_version: u32,
    pub other_versions: Vec<u32>,
}

impl TransportParams {
    // Decode transport parameters from the given buffer.
    pub(crate) fn decode(mut buf: &[u8]) -> Result<(TransportParams, usize)> {
        let len = buf.len();
        let mut tp = TransportParams::default();
        let mut found_params = HashSet::new();

        while !buf.is_empty() {
            let id = buf.read_varint()?;
            if found_params.contains(&id) {
                return Err(Error::TransportParameterError);
            }
            found_params.insert(id);

            let val = buf.read_with_varint_length()?;
            let mut val = val.as_slice();
            match id {
                0x0000 => {
                    // This transport parameter is only sent by a server.
                    tp.original_destination_connection_id = Some(ConnectionId::new(val));
                }

                0x0001 => {
                    tp.max_idle_timeout = val.read_varint()?;
                }

                0x0002 => {
                    // This transport parameter MUST NOT be sent by a client
                    // but MAY be sent by a server.
                    tp.stateless_reset_token = Some(u128::from_be_bytes(
                        val.read(16)?
                            .to_vec()
                            .try_into()
                            .map_err(|_| Error::BufferTooShort)?,
                    ));
                }

                0x0003 => {
                    tp.max_udp_payload_size = val.read_varint()?;
                    // Values below 1200 are invalid.
                    if tp.max_udp_payload_size < 1200 {
                        return Err(Error::TransportParameterError);
                    }
                }

                0x0004 => {
                    tp.initial_max_data = val.read_varint()?;
                }

                0x0005 => {
                    tp.initial_max_stream_data_bidi_local = val.read_varint()?;
                }

                0x0006 => {
                    tp.initial_max_stream_data_bidi_remote = val.read_varint()?;
                }

                0x0007 => {
                    tp.initial_max_stream_data_uni = val.read_varint()?;
                }

                0x0008 => {
                    let max = val.read_varint()?;
                    if max > MAX_STREAMS_PER_TYPE {
                        return Err(Error::TransportParameterError);
                    }
                    tp.initial_max_streams_bidi = max;
                }

                0x0009 => {
                    let max = val.read_varint()?;
                    if max > MAX_STREAMS_PER_TYPE {
                        return Err(Error::TransportParameterError);
                    }
                    tp.initial_max_streams_uni = max;
                }

                0x000a => {
                    let ack_delay_exponent = val.read_varint()?;
                    // Values above 20 are invalid.
                    if ack_delay_exponent > 20 {
                        return Err(Error::TransportParameterError);
                    }
                    tp.ack_delay_exponent = ack_delay_exponent;
                }

                0x000b => {
                    let max_ack_delay = val.read_varint()?;
                    // Values of 2^14 or greater are invalid.
                    if max_ack_delay >= 2_u64.pow(14) {
                        return Err(Error::TransportParameterError);
                    }
                    tp.max_ack_delay = max_ack_delay;
                }

                0x000c => {
                    tp.disable_active_migration = true;
                }

                0x000d => {
                    // This transport parameter is only sent by a server.
                    tp.preferred_address = Some(PreferredAddress::from_bytes(val)?.0);
                }

                0x000e => {
                    let limit = val.read_varint()?;
                    // The value of active_connection_id_limit parameter MUST
                    // be at least 2.
                    if limit < 2 {
                        return Err(Error::TransportParameterError);
                    }
                    tp.active_conn_id_limit = limit;
                }

                0x000f => {
                    tp.initial_source_connection_id = Some(ConnectionId::new(val));
                }

                0x00010 => {
                    // This transport parameter is only sent by a server.
                    tp.retry_source_connection_id = Some(ConnectionId::new(val));
                }

                0x0f739bbc1b666d05 => {
                    tp.enable_multipath = true;
                }

                0xbaad => {
                    tp.disable_encryption = true;
                }

                0x0020 => {
                    // max_datagram_frame_size
                    tp.max_datagram_frame_size = val.read_varint()?;
                }

                0x0011 => {
                    // version_information: chosen_version (4 bytes) + zero or more other versions (4 bytes each)
                    if val.len() < 8 || val.len() % 4 != 0 {
                        return Err(Error::TransportParameterError);
                    }
                    let chosen = u32::from_be_bytes(
                        val.read(4)?.try_into().map_err(|_| Error::BufferTooShort)?,
                    );
                    let mut others = vec![];
                    while !val.is_empty() {
                        let v = u32::from_be_bytes(
                            val.read(4)?.try_into().map_err(|_| Error::BufferTooShort)?,
                        );
                        others.push(v);
                    }
                    tp.version_information = Some(VersionInformation {
                        chosen_version: chosen,
                        other_versions: others,
                    });
                }

                0x4752 => {
                    // google_quic_version: 4 bytes
                    if val.len() != 4 {
                        return Err(Error::TransportParameterError);
                    }
                    tp.google_quic_version = Some(u32::from_be_bytes(
                        val.read(4)?.try_into().map_err(|_| Error::BufferTooShort)?,
                    ));
                }

                0x3127 => {
                    // google_initial_rtt: varint microseconds
                    let irtt = val.read_varint()?;
                    tp.google_initial_rtt = Some(u32::try_from(irtt).unwrap_or(u32::MAX));
                }

                // Ignore unknown parameters.
                _ => (),
            }
        }

        Ok((tp, len - buf.len()))
    }

    // Encode Transport parameters to the given buffer.
    pub(crate) fn encode(tp: &TransportParams, mut buf: &mut [u8]) -> Result<usize> {
        let total = buf.len();

        // Build parameter ID list and shuffle order to mimic browser behavior.
        const GREASE_SENTINEL: u64 = u64::MAX;
        let mut ids = vec![
            0x0000,             // original_destination_connection_id
            0x0001,             // max_idle_timeout
            0x0002,             // stateless_reset_token
            0x0003,             // max_udp_payload_size
            0x0004,             // initial_max_data
            0x0005,             // initial_max_stream_data_bidi_local
            0x0006,             // initial_max_stream_data_bidi_remote
            0x0007,             // initial_max_stream_data_uni
            0x0008,             // initial_max_streams_bidi
            0x0009,             // initial_max_streams_uni
            0x000c,             // disable_active_migration
            0x000d,             // preferred_address
            0x000f,             // initial_source_connection_id (always include)
            0x0010,             // retry_source_connection_id
            0x0011,             // version_information (12 bytes in our defaults)
            0x0020,             // max_datagram_frame_size
            0x4752,             // google_quic_version
            0x3127,             // google_initial_rtt
            0xbaad,             // disable_encryption
            0x0f739bbc1b666d05, // enable_multipath
            GREASE_SENTINEL,    // GREASE param (random id/value)
        ];

        // Shuffle order, but probabilistically omit some optional params to keep size small.
        // Drop preferred_address, stateless_reset_token, retry_source_connection_id by default.
        ids.retain(|id| !matches!(
            *id,
            0x0002 /* stateless_reset_token */ | 0x000d /* preferred_address */ | 0x0010 /* retry_scid */
        ));
        for i in (1..ids.len()).rev() {
            let j = (rand::rng().next_u32() as usize) % (i + 1);
            ids.swap(i, j);
        }

        for id in ids {
            let wrote = Self::encode_one_param(id, tp, buf)?;
            buf = &mut buf[wrote..];
        }

        Ok(total - buf.len())
    }

    fn encode_one_param(id: u64, tp: &TransportParams, mut buf: &mut [u8]) -> Result<usize> {
        let start = buf.len();
        match id {
            0x0000 => {
                if let Some(odcid) = &tp.original_destination_connection_id {
                    buf.write_varint(0x0000)?;
                    buf.write_varint(odcid.len() as u64)?;
                    buf.write(odcid)?;
                }
            }
            0x0001 => {
                if tp.max_idle_timeout != 0 {
                    buf.write_varint(0x0001)?;
                    buf.write_varint(codec::encode_varint_len(tp.max_idle_timeout) as u64)?;
                    buf.write_varint(tp.max_idle_timeout)?;
                }
            }
            0x0002 => {
                if let Some(token) = tp.stateless_reset_token {
                    buf.write_varint(0x0002)?;
                    buf.write_varint(16)?;
                    buf.write(&token.to_be_bytes())?;
                }
            }
            0x0003 => {
                if tp.max_udp_payload_size != 0 {
                    buf.write_varint(0x0003)?;
                    buf.write_varint(codec::encode_varint_len(tp.max_udp_payload_size) as u64)?;
                    buf.write_varint(tp.max_udp_payload_size)?;
                }
            }
            0x0004 => {
                if tp.initial_max_data != 0 {
                    buf.write_varint(0x0004)?;
                    buf.write_varint(codec::encode_varint_len(tp.initial_max_data) as u64)?;
                    buf.write_varint(tp.initial_max_data)?;
                }
            }
            0x0005 => {
                if tp.initial_max_stream_data_bidi_local != 0 {
                    buf.write_varint(0x0005)?;
                    buf.write_varint(
                        codec::encode_varint_len(tp.initial_max_stream_data_bidi_local) as u64,
                    )?;
                    buf.write_varint(tp.initial_max_stream_data_bidi_local)?;
                }
            }
            0x0006 => {
                if tp.initial_max_stream_data_bidi_remote != 0 {
                    buf.write_varint(0x0006)?;
                    buf.write_varint(codec::encode_varint_len(
                        tp.initial_max_stream_data_bidi_remote,
                    ) as u64)?;
                    buf.write_varint(tp.initial_max_stream_data_bidi_remote)?;
                }
            }
            0x0007 => {
                if tp.initial_max_stream_data_uni != 0 {
                    buf.write_varint(0x0007)?;
                    buf.write_varint(
                        codec::encode_varint_len(tp.initial_max_stream_data_uni) as u64
                    )?;
                    buf.write_varint(tp.initial_max_stream_data_uni)?;
                }
            }
            0x0008 => {
                if tp.initial_max_streams_bidi != 0 {
                    buf.write_varint(0x0008)?;
                    buf.write_varint(codec::encode_varint_len(tp.initial_max_streams_bidi) as u64)?;
                    buf.write_varint(tp.initial_max_streams_bidi)?;
                }
            }
            0x0009 => {
                if tp.initial_max_streams_uni != 0 {
                    buf.write_varint(0x0009)?;
                    buf.write_varint(codec::encode_varint_len(tp.initial_max_streams_uni) as u64)?;
                    buf.write_varint(tp.initial_max_streams_uni)?;
                }
            }
            0x000a => {
                if tp.ack_delay_exponent != 0 {
                    buf.write_varint(0x000a)?;
                    buf.write_varint(codec::encode_varint_len(tp.ack_delay_exponent) as u64)?;
                    buf.write_varint(tp.ack_delay_exponent)?;
                }
            }
            0x000c => {
                if tp.disable_active_migration {
                    buf.write_varint(0x000c)?;
                    buf.write_varint(0)?;
                }
            }
            0x000d => {
                if let Some(ref preferred_address) = tp.preferred_address {
                    buf.write_varint(0x000d)?;
                    buf.write_varint(preferred_address.wire_len() as u64)?;
                    let wlen = preferred_address.to_bytes(buf)?;
                    buf = &mut buf[wlen..];
                }
            }
            0x000f => {
                // Always include, even if empty
                buf.write_varint(0x000f)?;
                if let Some(scid) = &tp.initial_source_connection_id {
                    buf.write_varint(scid.len() as u64)?;
                    buf.write(scid)?;
                } else {
                    buf.write_varint(0)?;
                }
            }
            0x0010 => {
                if let Some(rcid) = &tp.retry_source_connection_id {
                    buf.write_varint(0x0010)?;
                    buf.write_varint(rcid.len() as u64)?;
                    buf.write(rcid)?;
                }
            }
            0x0011 => {
                if let Some(vi) = &tp.version_information {
                    let total_len = 4 * (1 + vi.other_versions.len());

                    buf.write_varint(0x0011)?;
                    buf.write_varint(total_len as u64)?;
                    buf.write_u32(vi.chosen_version)?;

                    let mut versions = vi.other_versions.clone();

                    for i in (1..versions.len()).rev() {
                        let j = (rand::rng().next_u32() as usize) % (i + 1);
                        versions.swap(i, j);
                    }

                    for v in &versions {
                        buf.write_u32(*v)?;
                    }
                }
            }
            0x0020 => {
                if tp.max_datagram_frame_size != 0 {
                    buf.write_varint(0x0020)?;
                    buf.write_varint(codec::encode_varint_len(tp.max_datagram_frame_size) as u64)?;
                    buf.write_varint(tp.max_datagram_frame_size)?;
                }
            }
            0x4752 => {
                if let Some(v) = tp.google_quic_version {
                    buf.write_varint(0x4752)?;
                    buf.write_varint(4)?;
                    buf.write_u32(v)?;
                }
            }
            0x3127 => {
                // Always send. If not configured, randomize a plausible microseconds value.
                let irtt_us: u32 = tp.google_initial_rtt.unwrap_or_else(|| {
                    // 1..=500 ms → us
                    let ms = (1 + (rand::rng().next_u32() % 500)) as u64;
                    (ms * 1000) as u32
                });
                buf.write_varint(0x3127)?;
                let irtt64 = irtt_us as u64;
                buf.write_varint(codec::encode_varint_len(irtt64) as u64)?;
                buf.write_varint(irtt64)?;
            }
            0xbaad => {
                if tp.disable_encryption {
                    buf.write_varint(0xbaad)?;
                    buf.write_varint(0)?;
                }
            }
            0x0f739bbc1b666d05 => {
                if tp.enable_multipath {
                    buf.write_varint(0x0f739bbc1b666d05)?;
                    buf.write_varint(0)?;
                }
            }
            u64::MAX => {
                let (grease_id, grease_val) = generate_grease_tp();
                buf.write_varint(grease_id)?;
                buf.write_varint(grease_val.len() as u64)?;
                buf.write(&grease_val)?;
            }
            _ => {}
        }
        Ok(start - buf.len())
    }

    /// Create TransportParametersSet event data for Qlog.
    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self, owner: qlog::events::Owner, cipher: Option<tls::Algorithm>) -> EventData {
        let original_destination_connection_id = Some(format!(
            "{:?}",
            self.original_destination_connection_id.as_ref()
        ));
        let stateless_reset_token = Some(format!("{:?}", self.stateless_reset_token.as_ref()));

        qlog::events::EventData::QuicParametersSet {
            owner: Some(owner),
            resumption_allowed: None,
            early_data_enabled: None,
            tls_cipher: Some(format!("{:?}", cipher)),
            original_destination_connection_id,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            stateless_reset_token,
            disable_active_migration: Some(self.disable_active_migration),
            max_idle_timeout: Some(self.max_idle_timeout),
            max_udp_payload_size: Some(self.max_udp_payload_size as u32),
            ack_delay_exponent: Some(self.ack_delay_exponent as u16),
            max_ack_delay: Some(self.max_ack_delay as u16),
            active_connection_id_limit: Some(self.active_conn_id_limit as u32),
            initial_max_data: Some(self.initial_max_data),
            initial_max_stream_data_bidi_local: Some(self.initial_max_stream_data_bidi_local),
            initial_max_stream_data_bidi_remote: Some(self.initial_max_stream_data_bidi_remote),
            initial_max_stream_data_uni: Some(self.initial_max_stream_data_uni),
            initial_max_streams_bidi: Some(self.initial_max_streams_bidi),
            initial_max_streams_uni: Some(self.initial_max_streams_uni),
            preferred_address: None,
            max_datagram_frame_size: if self.max_datagram_frame_size != 0 {
                Some(self.max_datagram_frame_size)
            } else {
                None
            },
            grease_quic_bit: None,
        }
    }
}

impl Default for TransportParams {
    fn default() -> TransportParams {
        TransportParams {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,

            // The default for this parameter is the maximum permitted UDP
            // payload of 65527.
            max_udp_payload_size: 65527,

            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,

            // If ack_delay_exponent parameter is absent, a default value of
            // 3 is assumed
            ack_delay_exponent: 3,

            // If max_ack_delay parameter is absent, a default of 25
            // milliseconds is assumed.
            max_ack_delay: 25,

            disable_active_migration: false,

            preferred_address: None,

            // The value of the active_connection_id_limit parameter MUST be
            // at least 2.
            active_conn_id_limit: 2,

            initial_source_connection_id: None,
            retry_source_connection_id: None,

            enable_multipath: false,
            disable_encryption: false,
            max_datagram_frame_size: 0,
            version_information: None,
            google_quic_version: None,
            google_initial_rtt: None,
        }
    }
}

/// A server's preferred address
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreferredAddress {
    pub ipv4_address: Option<SocketAddrV4>,
    pub ipv6_address: Option<SocketAddrV6>,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    pub fn wire_len(&self) -> usize {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() + 16
    }

    pub fn to_bytes(&self, mut buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();
        if let Some(addr) = self.ipv4_address {
            buf.write(&addr.ip().octets())?;
            buf.write_u16(addr.port())?;
        } else {
            buf.write(&Ipv4Addr::UNSPECIFIED.octets())?;
            buf.write_u16(0)?;
        }

        if let Some(addr) = self.ipv6_address {
            buf.write(&addr.ip().octets())?;
            buf.write_u16(addr.port())?;
        } else {
            buf.write(&Ipv6Addr::UNSPECIFIED.octets())?;
            buf.write_u16(0)?;
        }

        buf.write_u8(self.connection_id.len() as u8)?;
        buf.write(&self.connection_id)?;

        buf.write(&self.stateless_reset_token)?;
        Ok(len - buf.len())
    }

    pub fn from_bytes(mut buf: &[u8]) -> Result<(PreferredAddress, usize)> {
        let len = buf.len();
        let ipv4_addr = buf.read_ipv4_addr()?;
        let ipv4_port = buf.read_u16()?;
        let ipv6_addr = buf.read_ipv6_addr()?;
        let ipv6_port = buf.read_u16()?;
        let cid_len = buf.read_u8()?;
        let cid = buf.read(cid_len as usize)?;
        let token = buf.read(crate::RESET_TOKEN_LEN)?;

        Ok((
            Self {
                ipv4_address: if ipv4_addr.is_unspecified() && ipv4_port == 0 {
                    None
                } else {
                    Some(SocketAddrV4::new(ipv4_addr, ipv4_port))
                },
                ipv6_address: if ipv6_addr.is_unspecified() && ipv6_port == 0 {
                    None
                } else {
                    Some(SocketAddrV6::new(ipv6_addr, ipv6_port, 0, 0))
                },
                connection_id: ConnectionId::new(&cid),
                stateless_reset_token: ResetToken::new(&token)?,
            },
            len - buf.len(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionId;

    #[test]
    fn transport_params_from_client() -> Result<()> {
        let tp = TransportParams {
            original_destination_connection_id: None,
            max_idle_timeout: 60,
            stateless_reset_token: None,
            max_udp_payload_size: 1300,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 2 * 1024 * 1024,
            initial_max_stream_data_bidi_remote: 1024 * 1024,
            initial_max_stream_data_uni: 3 * 1024 * 1024,
            initial_max_streams_bidi: 200,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: true,
            preferred_address: None,
            active_conn_id_limit: 2,
            initial_source_connection_id: Some(ConnectionId::random()),
            retry_source_connection_id: None,
            enable_multipath: true,
            disable_encryption: false,
            max_datagram_frame_size: 0,
            version_information: None,
            google_quic_version: None,
            google_initial_rtt: Some(100000),
        };

        // encode on the client side
        let mut raw_params = [0; 256];
        let len = TransportParams::encode(&tp, &mut raw_params)?;

        // decode on the server side
        let (tp2, len2) = TransportParams::decode(&raw_params[..len])?;
        assert_eq!(tp, tp2);
        assert_eq!(len, len2);

        Ok(())
    }

    #[test]
    fn preferred_address() -> Result<()> {
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let ip6 = Ipv6Addr::new(0x26, 0, 0x1c9, 0, 0, 0xafc8, 0x10, 0x1);
        let addrs = [
            PreferredAddress {
                ipv4_address: Some(SocketAddrV4::new(ip4, 80)),
                ipv6_address: None,
                connection_id: ConnectionId::random(),
                stateless_reset_token: ResetToken([0xc; crate::RESET_TOKEN_LEN]),
            },
            PreferredAddress {
                ipv4_address: None,
                ipv6_address: Some(SocketAddrV6::new(ip6, 81, 0, 0)),
                connection_id: ConnectionId::random(),
                stateless_reset_token: ResetToken([0xc; crate::RESET_TOKEN_LEN]),
            },
            PreferredAddress {
                ipv4_address: Some(SocketAddrV4::new(ip4, 80)),
                ipv6_address: Some(SocketAddrV6::new(ip6, 81, 0, 0)),
                connection_id: ConnectionId::random(),
                stateless_reset_token: ResetToken([0xc; crate::RESET_TOKEN_LEN]),
            },
        ];

        for addr in addrs {
            let len = addr.wire_len();
            let mut buf = vec![0; len];
            assert_eq!(addr.to_bytes(&mut buf)?, len);

            let (addr2, len2) = PreferredAddress::from_bytes(&mut buf)?;
            assert_eq!(addr, addr2);
            assert_eq!(len, len2);
        }

        Ok(())
    }
}
