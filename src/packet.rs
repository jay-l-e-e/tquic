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

use std::fmt::Display;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;

use bytes::Bytes;
use bytes::BytesMut;
use rand::RngCore;
use ring::aead;

use self::PacketType::*;
use crate::ConnectionId;
use crate::Error;
use crate::MAX_CID_LEN;
use crate::Result;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::connection::space::SpaceId;
#[cfg(feature = "qlog")]
use crate::qlog;
use crate::ranges;
use crate::tls;
use crate::tls::Level;
use crate::tls::Open;
use crate::tls::Seal;

/// The most significant bit (0x80) of the first byte is set to 1 for
/// packet that use the long header.
const HEADER_LONG_FORM_BIT: u8 = 0x80;

/// The fixed bit of the first byte of packet header.
const HEADER_FIXED_BIT: u8 = 0x40;

/// The bit indicating the key phase for 1RTT packets.
const HEADER_KEY_PHASE_BIT: u8 = 0x04;

/// The packet type bits for packet that use the long header.
const PKT_TYPE_MASK: u8 = 0x30;

/// In packet that contain a Packet Number field, the least significant two
/// bits (those with a mask of 0x03) of the first byte contain the length of
/// the Packet Number field.
const PKT_NUM_LEN_MASK: u8 = 0x03;

/// The packet number field is 1 to 4 bytes long.
const MAX_PKT_NUM_LEN: usize = 4;

/// The cipher suites defined in TLS13 (other than TLS_AES_128_CCM_8_SHA256)
/// have 16-byte expansions and 16-byte header protection samples.
const SAMPLE_LEN: usize = 16;

/// The secret key for computing Retry Integrity Tag using AEAD_AES_128_GCM
/// algorithm. It is 128 bits equal to 0xbe0c690b9f66575a1d766b54e368c84e.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The nonce for computing Retry Integrity Tag using AEAD_AES_128_GCM
/// algorithm. It is 96 bits equal to 0x461599d35d632bf2239825bb.
const RETRY_INTEGRITY_NONCE_V1: [u8; aead::NONCE_LEN] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// QUIC packet type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// The Version Negotiation packet is a response to a client packet that
    /// contains a version that is not supported by the server.
    VersionNegotiation,

    /// Initial packet carries the first CRYPTO frames sent by the client and
    /// server to perform key exchange.
    Initial,

    /// 0-RTT packet is used to carry "early" data from the client to the
    /// server as part of the first flight, prior to handshake completion.
    ZeroRTT,

    /// Handshake packet is used to carry cryptographic handshake messages and
    /// acknowledgments from the server and client.
    Handshake,

    /// Retry packet carries an address validation token created by the server.
    /// It is used by a server that wishes to perform a retry
    Retry,

    /// 1-RTT packet is used after the version and 1-RTT keys are negotiated.
    OneRTT,
}

impl PacketType {
    /// Get encryption level for the given packet type.
    ///
    /// Data is protected using a number of encryption levels: Initial keys,
    /// Early data (0-RTT) keys, Handshake keys, Application data (1-RTT) keys.
    /// See RFC 9001 Section 2.1
    pub fn to_level(self) -> Result<Level> {
        match self {
            Initial => Ok(Level::Initial),
            ZeroRTT => Ok(Level::ZeroRTT),
            Handshake => Ok(Level::Handshake),
            OneRTT => Ok(Level::OneRTT),
            _ => Err(Error::InternalError),
        }
    }

    /// Get packet number space for the given packet type.
    ///
    /// Packet numbers are divided into three spaces in QUIC: Initial space,
    /// Handshake space, Application data space.
    /// See RFC 9000 Section 12.3
    pub fn to_space(self) -> Result<SpaceId> {
        match self {
            Initial => Ok(SpaceId::Initial),
            Handshake => Ok(SpaceId::Handshake),
            ZeroRTT | OneRTT => Ok(SpaceId::Data),
            _ => Err(Error::InternalError),
        }
    }

    /// Get the packet type for Qlog.
    #[cfg(feature = "qlog")]
    pub fn to_qlog(self) -> qlog::events::PacketType {
        match self {
            VersionNegotiation => qlog::events::PacketType::VersionNegotiation,
            Initial => qlog::events::PacketType::Initial,
            ZeroRTT => qlog::events::PacketType::ZeroRtt,
            Handshake => qlog::events::PacketType::Handshake,
            Retry => qlog::events::PacketType::Retry,
            OneRTT => qlog::events::PacketType::OneRtt,
        }
    }
}

/// QUIC packet header.
///
/// In order to simplify the processing of packet header, a generic header type
/// is intentionally used here.
#[derive(Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// The type of the packet.
    pub pkt_type: PacketType,

    /// The version in the long header packet.
    pub version: u32,

    /// The destination connection ID.
    pub dcid: ConnectionId,

    /// The source connection ID in long header packet.
    pub scid: ConnectionId,

    /// The length of the packet number.
    pub pkt_num_len: usize,

    /// The packet number.
    pub pkt_num: u64,

    /// The address verification token (Initial/Retry).
    pub token: Option<Vec<u8>>,

    /// The key phase bit (OneRTT).
    pub key_phase: bool,
}

impl PacketHeader {
    /// Encode a QUIC packet header to the given buffer.
    ///
    /// The Length/Packet Number field are intentionally not written to the
    /// buffer for the moment.
    /// See RFC 9000 Section 17 Packet Formats
    pub fn to_bytes(&self, mut buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();

        // Encode in short header form for OneRTT.
        //
        // 1-RTT Packet {
        //   Header Form (1) = 0,
        //   Fixed Bit (1) = 1,
        //   Spin Bit (1),
        //   Reserved Bits (2),
        //   Key Phase (1),
        //   Packet Number Length (2),
        //   Destination Connection ID (0..160),
        //   Packet Number (8..32),
        //   Packet Payload (8..),
        // }
        if self.pkt_type == OneRTT {
            let mut first = HEADER_FIXED_BIT;
            if self.key_phase {
                first |= HEADER_KEY_PHASE_BIT;
            }
            first |= self.pkt_num_len.saturating_sub(1) as u8;
            buf.write_u8(first)?;
            buf.write(&self.dcid)?;
            return Ok(len - buf.len());
        }

        // Encode in long header form.
        //
        // Long Header Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2),
        //   Type-Specific Bits (4),
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Type-Specific Payload (..),
        // }
        let mut first = HEADER_LONG_FORM_BIT | HEADER_FIXED_BIT;
        let pkt_type: u8 = match self.pkt_type {
            Initial => 0x00,
            ZeroRTT => 0x01,
            Handshake => 0x02,
            Retry => 0x03,
            _ => return Err(Error::InternalError),
        };
        first |= pkt_type << 4;
        first |= self.pkt_num_len.saturating_sub(1) as u8;
        buf.write_u8(first)?;
        buf.write_u32(self.version)?;
        buf.write_u8(self.dcid.len() as u8)?;
        buf.write(&self.dcid)?;
        buf.write_u8(self.scid.len() as u8)?;
        buf.write(&self.scid)?;

        // Type specific fields for Initial and Retry
        match self.pkt_type {
            Initial => match self.token {
                // Token length and Token
                Some(ref v) => {
                    buf.write_varint(v.len() as u64)?;
                    buf.write(v)?;
                }
                None => {
                    buf.write_varint(0)?;
                }
            },
            Retry => {
                // Token
                buf.write(self.token.as_ref().unwrap())?;
            }
            _ => (),
        }

        Ok(len - buf.len())
    }

    /// Decode a QUIC packet header from the given buffer.
    ///
    /// The `dcid_len` is required for parsing OneRTT packets.
    /// The Length/Packet Number field in packet header are intentionally not
    /// read from the buffer for the moment.
    ///
    /// See RFC 9000 Section 17 Packet Formats
    pub fn from_bytes(mut buf: &[u8], dcid_len: usize) -> Result<(PacketHeader, usize)> {
        let len = buf.len();
        let first = buf.read_u8()?;

        // Decode in short header form for 1-RTT.
        if !PacketHeader::long_header(first) {
            let dcid = buf.read(dcid_len)?;

            return Ok((
                PacketHeader {
                    pkt_type: OneRTT,
                    version: 0,
                    dcid: ConnectionId::new(&dcid),
                    scid: ConnectionId::default(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token: None,
                    key_phase: false,
                },
                len - buf.len(),
            ));
        }

        // Decode in long header form.
        let version = buf.read_u32()?;
        let pkt_type = if version == 0 {
            VersionNegotiation
        } else {
            match (first & PKT_TYPE_MASK) >> 4 {
                0x00 => Initial,
                0x01 => ZeroRTT,
                0x02 => Handshake,
                0x03 => Retry,
                _ => return Err(Error::InvalidPacket),
            }
        };

        let dcid_len = buf.read_u8()?;
        if crate::version_is_supported(version) && dcid_len > MAX_CID_LEN as u8 {
            return Err(Error::InvalidPacket);
        }
        let dcid = buf.read(dcid_len as usize)?;
        let scid_len = buf.read_u8()?;
        if crate::version_is_supported(version) && scid_len > MAX_CID_LEN as u8 {
            return Err(Error::InvalidPacket);
        }
        let scid = buf.read(scid_len as usize)?;

        // Type specific fields for Initial and Retry
        let mut token: Option<Vec<u8>> = None;
        match pkt_type {
            Initial => {
                let token_len = buf.read_varint()?;
                if token_len > 0 {
                    token = Some(buf.read(token_len as usize)?);
                }
            }
            Retry => {
                // Exclude the integrity tag from the token.
                if buf.len() < aead::AES_128_GCM.tag_len() {
                    return Err(Error::InvalidPacket);
                }
                let token_len = buf.len() - aead::AES_128_GCM.tag_len();
                token = Some(buf.read(token_len)?);
            }
            _ => (),
        };

        Ok((
            PacketHeader {
                pkt_type,
                version,
                dcid: ConnectionId::new(&dcid),
                scid: ConnectionId::new(&scid),
                pkt_num: 0,
                pkt_num_len: 0,
                token,
                key_phase: false,
            },
            len - buf.len(),
        ))
    }

    /// Extract the header form, version and destination connection id.
    ///
    /// Return (true, version, cid) for the quic packet with a long header
    /// Return (false, 0, cid) for the quic packet with a short header
    /// See RFC 8999 Section 5
    pub fn header_info(mut buf: &[u8], dcid_len: usize) -> Result<(bool, u32, ConnectionId)> {
        let first = buf.read_u8()?;

        // Decode in short header form for 1-RTT.
        if !PacketHeader::long_header(first) {
            let dcid = buf.read(dcid_len)?;
            let dcid = ConnectionId::new(&dcid);
            return Ok((false, 0, dcid));
        }

        // Decode in long header form.
        let version = buf.read_u32()?;
        let dcid_len = buf.read_u8()?;
        let dcid = buf.read(dcid_len as usize)?;
        let dcid = ConnectionId::new(&dcid);
        Ok((true, version, dcid))
    }

    /// Return true if the packet has a long header.
    fn long_header(header_first_byte: u8) -> bool {
        header_first_byte & HEADER_LONG_FORM_BIT != 0
    }
}

impl std::fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.pkt_type)?;
        if self.pkt_type != OneRTT {
            write!(f, " ver={:x}", self.version)?;
        }

        write!(f, " dcid={:?}", self.dcid)?;
        if self.pkt_type != OneRTT {
            write!(f, " scid={:?}", self.scid)?;
        }

        if let Some(ref token) = self.token {
            write!(f, " token=")?;
            for b in token {
                write!(f, "{b:02x}")?;
            }
        }
        if self.pkt_type == OneRTT {
            write!(f, " key_phase={}", self.key_phase)?;
        }

        Ok(())
    }
}

/// Encrypt payload and header fields of a QUIC packet.
///
/// The `pkt_buf` is the raw data of packet in plaintext.
/// The `pkt_num` is the packet sequence number.
/// The `pkt_num_len` is the encoded length of packet sequence number.
/// The `payload_len` is the length of packet payload in plaintext.
/// The `payload_offset` is the offset of packet payload in `pkt_buf`.
///
/// See RFC 9001 Section 5.3
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_packet(
    pkt_buf: &mut [u8],
    cid_seq: Option<u32>,
    pkt_num: u64,
    pkt_num_len: usize,
    payload_len: usize,
    payload_offset: usize,
    extra_in: Option<&[u8]>,
    aead: &Seal,
) -> Result<usize> {
    if pkt_buf.len() < payload_offset + payload_len {
        return Err(Error::BufferTooShort);
    }

    // Packet header starts from the first byte of either the short or long
    // header, up to and including the unprotected packet number.
    let (pkt_hdr, payload) = pkt_buf.split_at_mut(payload_offset);

    // Encrypt packet payload
    let ciphertext_len = aead.seal(
        cid_seq,
        pkt_num,     // for nonce
        pkt_hdr,     // associated data
        payload,     // plaintext
        payload_len, // length of plaintext
        extra_in,
    )?;

    // Encrypt packet header fields
    encrypt_header(pkt_hdr, pkt_num_len, payload, aead)?;

    Ok(payload_offset + ciphertext_len)
}

/// Apply header protection for a QUIC packet.
///
/// Header protection is applied after packet protection is applied.
/// See RFC 9001 Section 5.4.1
fn encrypt_header(
    hdr_buf: &mut [u8],
    pkt_num_len: usize,
    payload: &[u8],
    aead: &Seal,
) -> Result<()> {
    // The sample of ciphertext is taken starting from an offset of 4 bytes
    // after the start of the Packet Number field.
    let sample_start = MAX_PKT_NUM_LEN - pkt_num_len;
    let sample = &payload[sample_start..sample_start + SAMPLE_LEN];

    // The ciphertext of the packet is sampled and used as input to an
    // encryption algorithm. The output is a 5-byte mask that is applied to
    // the protected header fields using exclusive OR.
    let mask = aead.new_mask(sample)?;

    // The four least significant bits of the first byte are protected for
    // packets with long headers; the five least significant bits of the first
    // byte are protected for packets with short headers.
    let (first, rest) = hdr_buf.split_at_mut(1);
    if PacketHeader::long_header(first[0]) {
        first[0] ^= mask[0] & 0x0f;
    } else {
        first[0] ^= mask[0] & 0x1f;
    }

    // Mask the Packet Number field. It is the last field in packet header.
    let (_, pkt_num_buf) = rest.split_at_mut(rest.len() - pkt_num_len);
    for i in 0..pkt_num_len {
        pkt_num_buf[i] ^= mask[i + 1];
    }

    Ok(())
}

/// Decrypt payload of a QUIC packet.
///
/// The `pkt_buf` is the raw data of a QUIC packet.
/// The `payload_offset` is the offset of packet payload in `pkt_buf`.
/// The `payload_len` is the length of pacekt payload (other than the value of Length field).
/// The `pkt_num` is the decrypted and decoded packet number.
#[allow(unexpected_cfgs)]
pub(crate) fn decrypt_payload(
    pkt_buf: &mut [u8],
    payload_offset: usize,
    payload_len: usize,
    cid_seq: Option<u32>,
    pkt_num: u64,
    aead: &Open,
) -> Result<bytes::Bytes> {
    if pkt_buf.len() < payload_offset + payload_len {
        return Err(Error::BufferTooShort);
    }

    let (header_buf, payload_buf) = pkt_buf.split_at_mut(payload_offset);
    let payload_buf = &mut payload_buf[..payload_len];
    let mut plaintext = BytesMut::zeroed(payload_len);

    if cfg!(feature = "fuzzing") {
        // Not touch payload for fuzz testing
        return Ok(Bytes::copy_from_slice(payload_buf));
    }

    let payload_len = aead.open(
        cid_seq,
        pkt_num,
        header_buf,
        payload_buf,
        &mut plaintext[..],
    )?;
    plaintext.truncate(payload_len);
    Ok(plaintext.freeze())
}

/// Remove header protection of a QUIC packet.
///
/// The `pkt_buf` is the raw data of a QUIC packet.
/// The `pkt_num_offset` is the offset of Packet Number field in `pkt_buf`.
/// The `hdr` is the partially parsed header return by PacketHeader::from().
/// The `plaintext_mode` is used for the `disable_1rtt_encryption` extension.
pub(crate) fn decrypt_header(
    pkt_buf: &mut [u8],
    pkt_num_offset: usize,
    hdr: &mut PacketHeader,
    aead: &Open,
    plaintext_mode: bool,
) -> Result<()> {
    let pkt_buf_min = if !plaintext_mode {
        pkt_num_offset + MAX_PKT_NUM_LEN + SAMPLE_LEN
    } else {
        // All aspects of encryption on 1-RTT packets are removed and it is no
        // longer including an AEAD tag.
        pkt_num_offset + MAX_PKT_NUM_LEN
    };
    if pkt_buf.len() < pkt_buf_min {
        return Err(Error::BufferTooShort);
    }

    // Decrypt packet haader if needed
    let mut first = pkt_buf[0];
    let (pkt_num_len, pkt_num_buf) = if !plaintext_mode {
        // Remove protection of bits in the first byte
        let sample_start = pkt_num_offset + MAX_PKT_NUM_LEN;
        let sample = &pkt_buf[sample_start..sample_start + SAMPLE_LEN];
        let mask = aead.new_mask(sample)?;
        if PacketHeader::long_header(first) {
            first ^= mask[0] & 0x0f;
        } else {
            first ^= mask[0] & 0x1f;
        }

        let pkt_num_len = usize::from((first & PKT_NUM_LEN_MASK) + 1);
        let pkt_num_buf = &mut pkt_buf[pkt_num_offset..pkt_num_offset + pkt_num_len];

        // Remove protection of packet number field
        for i in 0..pkt_num_len {
            pkt_num_buf[i] ^= mask[i + 1];
        }
        (pkt_num_len, pkt_num_buf)
    } else {
        let pkt_num_len = usize::from((first & PKT_NUM_LEN_MASK) + 1);
        let pkt_num_buf = &mut pkt_buf[pkt_num_offset..pkt_num_offset + pkt_num_len];
        (pkt_num_len, pkt_num_buf)
    };

    // Extract packet number corresponding to the length.
    let pkt_num = {
        let mut b: &[u8] = pkt_num_buf;
        match pkt_num_len {
            1 => u64::from(b.read_u8()?),
            2 => u64::from(b.read_u16()?),
            3 => u64::from(b.read_u24()?),
            4 => u64::from(b.read_u32()?),
            _ => return Err(Error::InvalidPacket),
        }
    };

    // Write the decrypted first byte back into the packet buffer.
    pkt_buf[0] = first;

    // Update the parsed packet header
    hdr.pkt_num_len = pkt_num_len;
    hdr.pkt_num = pkt_num;
    if hdr.pkt_type == OneRTT {
        hdr.key_phase = (first & HEADER_KEY_PHASE_BIT) != 0;
    }
    Ok(())
}

/// Decode packet number after header protection has been removed.
///
/// The `largest_pn` is the largest packet number that has been successfully
/// processed in the current packet number space.
/// The `truncated_pn` is the value of the Packet Number field.
/// The `pkt_num_len` is the number of bits in the Packet Number field.
/// See RFC 9000 Section A.3 Sample Packet Number Decoding Algorithm
pub(crate) fn decode_packet_num(largest_pn: u64, truncated_pn: u64, pkt_num_len: usize) -> u64 {
    let pn_nbits = pkt_num_len * 8;
    let expected_pn = largest_pn + 1;
    let pn_win = 1 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    // The incoming packet number should be greater than expected_pn - pn_hwin
    // and less than or equal to expected_pn + pn_hwin .
    //
    // This means we cannot just strip the trailing bits from expected_pn and
    // add the truncated_pn because that might yield a value outside the window.
    //
    // The following code calculates a candidate value and makes sure it's
    // within the packet number window.
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;
    if candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1 << 62) - pn_win {
        return candidate_pn + pn_win;
    }
    if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        return candidate_pn - pn_win;
    }
    candidate_pn
}

/// Encode the full packet number.
///
/// Packet numbers are encoded in 1 to 4 bytes. The number of bits required to
/// represent the packet number is reduced by including only the least
/// significant bits of the packet number.
///
/// The `pkt_num` is the full packet number of the packet being sent.
/// The `len` is the length of encoded packet number.
/// See RFC 9000 Section A.2 Sample Packet Number Encoding Algorithm
pub(crate) fn encode_packet_num(pkt_num: u64, len: usize, mut buf: &mut [u8]) -> Result<usize> {
    // Encode the integer value and truncate to the num_bytes least significant
    // bytes.
    match len {
        1 => buf.write_u8(pkt_num as u8)?,
        2 => buf.write_u16(pkt_num as u16)?,
        3 => buf.write_u24(pkt_num as u32)?,
        4 => buf.write_u32(pkt_num as u32)?,
        _ => return Err(Error::InvalidPacket),
    };

    Ok(len)
}

/// Return the length of encoded packet number.
///
/// The `pkt_num` is the full packet number of the packet being sent.
/// The `largest_acked` is the largest packet number that has been acknowledged
/// by the peer in the current packet number space, if any.
/// See RFC 9000 Section A.2 Sample Packet Number Encoding Algorithm
pub(crate) fn packet_num_len(pkt_num: u64, largest_acked: Option<u64>) -> usize {
    // The number of bits must be at least one more than the base-2 logarithm
    // of the number of contiguous unacknowledged packet numbers, including the
    // new packet
    let num_unacked = if let Some(largest_acked) = largest_acked {
        pkt_num.saturating_sub(largest_acked)
    } else {
        pkt_num.saturating_add(1)
    };

    let min_bits = u64::BITS - num_unacked.leading_zeros() + 1; // ceil(log(num_unacked, 2)) + 1
    min_bits.div_ceil(8) as usize // ceil(min_bits / 8)
}

/// Encode a Version Negotiation packet to the given buffer
///
/// The `scid` is the source CID of the Version Negotiation packet.
/// The `dcid` is the destination CID of the Version Negotiation packet.
pub fn version_negotiation(scid: &[u8], dcid: &[u8], mut buf: &mut [u8]) -> Result<usize> {
    let len = buf.len();

    let first = rand::random::<u8>() | HEADER_LONG_FORM_BIT;
    buf.write_u8(first)?;

    // A Version Negotiation packet is inherently not version specific. It will
    // be identified as a Version Negotiation packet based on the Version field
    // having a value of 0.
    buf.write_u32(0)?;

    buf.write_u8(dcid.len() as u8)?;
    buf.write(dcid)?;
    buf.write_u8(scid.len() as u8)?;
    buf.write(scid)?;

    // The remainder of the Version Negotiation packet is a list of 32-bit
    // versions that the server supports
    buf.write_u32(crate::QUIC_VERSION_V1)?;

    Ok(len - buf.len())
}

/// Encode a Retry packet to the given buffer
///
/// The `scid` is the scid of Retry packet.
/// The `dcid` is the scid of Retry packet.
/// The `odcid` is the original dcid of the Initial packet.
pub fn retry(
    scid: &[u8],
    dcid: &[u8],
    odcid: &[u8],
    token: &[u8],
    version: u32,
    out: &mut [u8],
) -> Result<usize> {
    if !crate::version_is_supported(version) {
        return Err(Error::UnknownVersion);
    }

    // Prepare Retry packet header
    let hdr = PacketHeader {
        pkt_type: Retry,
        version,
        dcid: ConnectionId::new(dcid),
        scid: ConnectionId::new(scid),
        pkt_num: 0,
        pkt_num_len: 0,
        token: Some(token.to_vec()),
        key_phase: false,
    };
    let hdr_len = hdr.to_bytes(out)?;

    // Compute and add integrity tag
    let tag = compute_retry_integrity_tag(&out[..hdr_len], odcid, version)?;
    let mut out = &mut out[hdr_len..];
    out.write(tag.as_ref())?;

    Ok(hdr_len + tag.as_ref().len())
}

/// Compute the Retry Packet Integrity Tag
///
/// See RFC 9001 Section 5.8 Retry Packet Integrity.
fn compute_retry_integrity_tag(retry_hdr: &[u8], odcid: &[u8], _version: u32) -> Result<aead::Tag> {
    // The Retry Pseudo-Packet is computed by taking the transmitted Retry
    // packet, removing the Retry Integrity Tag, and prepending the two
    // following fields: Original DCID Length, Original DCID
    let mut pseudo_pkt = vec![0_u8; 1 + odcid.len() + retry_hdr.len()];
    let mut pb = pseudo_pkt.as_mut_slice();
    pb.write_u8(odcid.len() as u8)?;
    pb.write(odcid)?;
    pb.write(retry_hdr)?;

    // The Retry Integrity Tag is a 128-bit field that is computed as the output
    // of AEAD_AES_128_GCM; The plaintext is empty; The associated data is the
    // contents of the Retry Pseudo-Packet
    let (key, nonce) = (&RETRY_INTEGRITY_KEY_V1, RETRY_INTEGRITY_NONCE_V1);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| Error::CryptoFail)?,
    );
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let aad = aead::Aad::from(&pseudo_pkt);
    key.seal_in_place_separate_tag(nonce, aad, &mut [])
        .map_err(|_| Error::CryptoFail)
}

/// Verify integrity tag of Retry packet
///
/// The `buf` is the octets of Retry packet.
/// The `odicd` is the original destination cid.
pub fn verify_retry_integrity_tag(buf: &mut [u8], odcid: &[u8], version: u32) -> Result<()> {
    let len = aead::AES_128_GCM.tag_len();
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }

    let hdr_buf = &buf[..buf.len() - len];
    let tag = compute_retry_integrity_tag(hdr_buf, odcid, version)?;
    #[allow(deprecated)]
    ring::constant_time::verify_slices_are_equal(&buf[buf.len() - len..], tag.as_ref())
        .map_err(|_| Error::CryptoFail)?;

    Ok(())
}

/// Encode a Stateless Reset packet to the given buffer
///
/// The `pkt_len` is the length of Stateless Reset packet.
/// The `token` is the Stateless Reset token.
pub fn stateless_reset(pkt_len: usize, token: &[u8], mut out: &mut [u8]) -> Result<usize> {
    if pkt_len > out.len() {
        return Err(Error::BufferTooShort);
    }
    if pkt_len < crate::MIN_RESET_PACKET_LEN {
        return Err(Error::InternalError);
    }
    if token.len() != crate::RESET_TOKEN_LEN {
        return Err(Error::InternalError);
    }

    // The layout of Stateless Reset packet:
    //
    // Stateless Reset {
    //   Fixed Bits (2) = 1,
    //   Unpredictable Bits (38..),
    //   Stateless Reset Token (128),
    // }

    // Write the Unpredictable Bits
    let unpredict_len = pkt_len - crate::RESET_TOKEN_LEN;
    rand::rng().fill_bytes(&mut out[..unpredict_len]);

    // Set the 2 fixed bits
    out[0] = (out[0] & 0b0011_1111) | HEADER_FIXED_BIT;

    // Write the Stateless Reset Token
    out = &mut out[unpredict_len..];
    out.write(token)?;
    Ok(pkt_len)
}
