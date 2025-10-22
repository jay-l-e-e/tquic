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

use std::collections::VecDeque;
use std::collections::hash_map;
use std::convert::TryFrom;
use std::mem::MaybeUninit;
use std::sync::Arc;

use bytes::Bytes;
use bytes::BytesMut;
use log::*;

use super::Header;
use super::frame;
use super::qpack;
use super::stream;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::connection::Connection;
use crate::connection::stream::StreamIdHashMap;
use crate::h3::Http3Config;
use crate::h3::Http3Error;
use crate::h3::Http3Event;
use crate::h3::Http3Handler;
use crate::h3::NameValue;
use crate::h3::Result;
use stream::Http3Stream;
use stream::Http3StreamState;
use stream::Http3StreamType;

// RFC9218 4.1. Urgency
// The urgency (u) parameter value is Integer (see Section 3.3.1 of [STRUCTURED-FIELDS]),
// between 0 and 7 inclusive, in descending order of priority. The default is 3.
const PRIORITY_URGENCY_LOWER_BOUND: u8 = 0;
const PRIORITY_URGENCY_UPPER_BOUND: u8 = 7;
const PRIORITY_URGENCY_DEFAULT: u8 = 3;
// RFC9218 4.2. Incremental
// The incremental (i) parameter value is Boolean (see Section 3.3.6 of [STRUCTURED-FIELDS]).
// It indicates if an HTTP response can be processed incrementally, i.e., provide some meaningful
// output as chunks of the response arrive.
// The default value of the incremental parameter is false (0).
const PRIORITY_INCREMENTAL_DEFAULT: bool = false;
// Map HTTP/3 urgency to QUIC urgency in a linear way with this offset, i.e., 1 maps to 125.
const PRIORITY_URGENCY_OFFSET: u8 = 124;

const INITIAL_UNI_STREAM_ID_CLIENT: u64 = 0x2;
const INITIAL_UNI_STREAM_ID_SERVER: u64 = 0x3;

/// An HTTP/3 connection.
pub struct Http3Connection {
    /// Collection of streams that are organized and accessed by stream ID.
    streams: StreamIdHashMap<Http3Stream>,

    /// Finished streams that need to be notified to the application.
    finished_streams: VecDeque<u64>,

    /// The local settings for the connection.
    local_settings: Http3Settings,
    /// The peer settings for the connection.
    peer_settings: Http3Settings,

    /// QPACK encoder.
    qpack_encoder: qpack::QpackEncoder,
    /// QPACK decoder.
    qpack_decoder: qpack::QpackDecoder,

    /// The streams for local QPACK.
    local_qpack_streams: QpackStreams,
    /// The streams for peer QPACK.
    peer_qpack_streams: QpackStreams,

    /// The next stream ID to be used for a request(bididirectional) stream.
    next_request_stream_id: u64,
    /// The next stream ID to be used for a unidirectional stream.
    next_uni_stream_id: u64,

    /// The control stream ID initiated by the local endpoint.
    local_control_stream_id: Option<u64>,
    /// The control stream ID initiated by the peer.
    peer_control_stream_id: Option<u64>,

    /// The ID of the GOAWAY frame sent by the local endpoint.
    local_goaway_id: Option<u64>,
    /// The ID of the GOAWAY frame received from the peer.
    peer_goaway_id: Option<u64>,

    /// The maximum push ID that the server can use in PUSH_PROMISE and CANCEL_PUSH frames.
    //  RFC9114 7.2.7 MAX_PUSH_ID
    //  The maximum push ID is unset when an HTTP/3 connection is created, meaning that a
    //  server cannot push until it receives a MAX_PUSH_ID frame. A client that wishes to
    //  manage the number of promised server pushes can increase the maximum push ID by
    //  sending MAX_PUSH_ID frames as the server fulfills or cancels server pushes.
    max_push_id: Option<u64>,

    /// Used to communicate with the application code.
    handler: Option<Arc<dyn Http3Handler>>,

    /// Unique trace id for deubg logging
    trace_id: String,
}

impl Http3Connection {
    /// Create a new HTTP/3 connection with the given configuration and role.
    fn new(config: &Http3Config) -> Result<Http3Connection> {
        let initial_uni_stream_id = INITIAL_UNI_STREAM_ID_CLIENT;

        Ok(Http3Connection {
            streams: Default::default(),

            finished_streams: VecDeque::new(),

            local_settings: Http3Settings {
                max_field_section_size: config.max_field_section_size,
                qpack_max_table_capacity: config.qpack_max_table_capacity,
                qpack_blocked_streams: config.qpack_blocked_streams,
                connect_protocol_enabled: None,
                raw: Default::default(),
            },

            peer_settings: Http3Settings {
                max_field_section_size: None,
                qpack_max_table_capacity: None,
                qpack_blocked_streams: None,
                connect_protocol_enabled: None,
                raw: Default::default(),
            },

            qpack_encoder: qpack::QpackEncoder::new(),
            qpack_decoder: qpack::QpackDecoder::new(),

            local_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },

            peer_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },

            next_request_stream_id: 0,
            next_uni_stream_id: initial_uni_stream_id,

            local_control_stream_id: None,
            peer_control_stream_id: None,

            local_goaway_id: None,
            peer_goaway_id: None,

            max_push_id: None,

            handler: None,

            trace_id: String::new(),
        })
    }

    /// Create a new HTTP/3 connection with the given QUIC transport connection and HTTP/3
    /// configuration, and initiate all HTTP/3 critical streams, including the control stream
    /// and QPACK encoder/decoder streams.
    pub fn new_with_quic_conn(
        conn: &mut Connection,
        config: &Http3Config,
    ) -> Result<Http3Connection> {
        // As a client, HTTP/3 connection can be created only when the QUIC connection is
        // established or in early data.
        #[allow(clippy::nonminimal_bool)]
        if !(conn.is_established() || conn.is_in_early_data()) {
            error!(
                "{:?} Client must not create an HTTP/3 connection if the QUIC connection has not
                been established or is in early data, is_established {}, is_in_early_data {}",
                conn.trace_id(),
                conn.is_established(),
                conn.is_in_early_data()
            );
            return Err(Http3Error::InternalError);
        }

        // Create an HTTP/3 connection with the QUIC transport connection.
        let mut http3_conn = Http3Connection::new(config)?;

        // Set trace id for debug logging
        http3_conn.trace_id = conn.trace_id().to_string();

        // Initiate all HTTP/3 critical streams, including the control stream and QPACK encoder/decoder streams.
        http3_conn.open_critical_streams(conn)?;

        Ok(http3_conn)
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or try to create a new one with given paras otherwise.
    fn get_or_create(&mut self, stream_id: u64, local: bool) -> Result<&mut Http3Stream> {
        match self.streams.entry(stream_id) {
            // 1. Stream doesn't exist, try to create it.
            hash_map::Entry::Vacant(v) => {
                // RFC9114 6.1. Bidirectional Streams
                // HTTP/3 does not use server-initiated bidirectional streams, though
                // an extension could define a use for these streams. Clients MUST treat
                // receipt of a server-initiated bidirectional stream as a connection
                // error of type H3_STREAM_CREATION_ERROR unless such an extension has
                // been negotiated.
                if crate::stream::is_bidi(stream_id) && !local {
                    Err(Http3Error::StreamCreationError)
                } else {
                    trace!("{} create new stream {}", self.trace_id, stream_id);
                    // Create a new HTTP/3 stream and insert it into streams map.
                    Ok(v.insert(Http3Stream::new(stream_id, local)))
                }
            }

            // 2.Stream already exists.
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// Update next request stream ID.
    fn update_next_request_stream_id(&mut self) -> Result<()> {
        if self.next_request_stream_id >= 1 << 62 {
            return Err(Http3Error::IdError);
        }

        self.next_request_stream_id += 4;
        Ok(())
    }

    /// Update next uni stream ID.
    fn update_next_uni_stream_id(&mut self) -> Result<()> {
        if self.next_uni_stream_id >= 1 << 62 {
            return Err(Http3Error::IdError);
        }

        self.next_uni_stream_id += 4;
        Ok(())
    }

    /// Set handler for HTTP/3 connection events.
    pub fn set_events_handler(&mut self, handler: Arc<dyn Http3Handler>) {
        self.handler = Some(handler);
    }

    /// Create a new HTTP/3 request stream.
    pub fn stream_new(&mut self, conn: &mut Connection) -> Result<u64> {
        self.stream_new_with_priority(conn, &Http3Priority::default())
    }

    /// Create a new HTTP/3 request stream with the given priority.
    pub fn stream_new_with_priority(
        &mut self,
        conn: &mut Connection,
        priority: &Http3Priority,
    ) -> Result<u64> {
        // Endpoint MUST NOT initiate new requests on the connection after receipt of
        // a GOAWAY frame from the peer.
        if self.peer_goaway_id.is_some() {
            return Err(Http3Error::IdError);
        }

        // Get the next available stream ID for new request.
        let stream_id = self.next_request_stream_id;

        // Create a new QUIC transport stream.
        conn.stream_new(stream_id, priority.map_to_quic(), priority.incremental)?;

        // Create a new HTTP/3 request stream and insert it into streams map.
        let mut stream = Http3Stream::new(stream_id, true);
        stream.mark_priority_initialized();
        self.streams.insert(stream_id, stream);

        // We only update next_request_stream_id when the new stream has been
        // created, to avoid skipping stream IDs.
        self.update_next_request_stream_id()?;

        trace!("{} create new stream {}", self.trace_id, stream_id);
        Ok(stream_id)
    }

    /// Close the given HTTP/3 stream.
    pub fn stream_close(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        if !stream_id.is_multiple_of(4) {
            // Only support closing request stream.
            return Err(Http3Error::InternalError);
        }

        if !self.streams.contains_key(&stream_id) {
            // Stream doesn't exist, ignore the prioritization.
            return Ok(());
        }

        if !conn.stream_finished(stream_id) {
            info!(
                "{:?} stream {} shutdown read prematurely",
                self.trace_id, stream_id
            );
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Read, 0);
        }

        let stream = self.streams.get(&stream_id).unwrap();
        if !stream.write_finished() {
            info!(
                "{:?} stream {} shutdown write prematurely",
                self.trace_id, stream_id
            );
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Write, 0);
        }

        self.stream_destroy(stream_id);
        Ok(())
    }

    /// Destroy the given stream.
    pub fn stream_destroy(&mut self, stream_id: u64) {
        trace!("{} destroy stream {}", self.trace_id, stream_id);
        self.streams.remove(&stream_id);
    }

    /// Set priority for an HTTP/3 stream.
    pub fn stream_set_priority(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        priority: &Http3Priority,
    ) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            // Stream doesn't exist, ignore the prioritization.
            return Ok(());
        }

        let urgency = priority.map_to_quic();
        conn.stream_set_priority(stream_id, urgency, priority.incremental)?;

        Ok(())
    }

    /// Encode HTTP/3 header fields into a field section with QPACK.
    fn encode_header_fields<T: NameValue>(&mut self, headers: &[T]) -> Result<Bytes> {
        // RFC9114: The default value of max_field_section_size is unlimited.
        let max_field_section_size = self
            .peer_settings
            .max_field_section_size
            .unwrap_or(u64::MAX);

        // RFC9114 4.2.2 Header Size Constraints
        // The size of a field list is calculated based on the uncompressed size of fields,
        // including the length of the name and value in bytes plus an overhead of 32 bytes
        // for each field.
        let headers_size = headers.iter().fold(0, |header_size, h| {
            header_size + h.value().len() + h.name().len() + 32
        });

        if headers_size as u64 > max_field_section_size {
            return Err(Http3Error::ExcessiveLoad);
        }

        let mut header_block = BytesMut::zeroed(headers_size);
        match self.qpack_encoder.encode(headers, header_block.as_mut()) {
            Ok(v) => {
                header_block.truncate(v);
                Ok(header_block.freeze())
            }
            Err(_) => Err(Http3Error::InternalError),
        }
    }

    /// Write HTTP/3 header block to quic stream buffer.
    fn send_header_block(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        header_block: Bytes,
        fin: bool,
    ) -> Result<()> {
        // HEADER_FRAME_TYPE(1Bytes) + header_block_len(1~8Bytes) <= 9Bytes.
        let mut bytes = BytesMut::zeroed(10);
        let mut b = bytes.as_mut();

        let header_block_len = header_block.len();
        let mut frame_header_len = b.write_varint(frame::HEADERS_FRAME_TYPE)?;
        frame_header_len += b.write_varint(header_block_len as u64)?;

        // We don't want to write headers multiple times, so we need to make sure
        // the stream has enough capacity to write the entire HEADERS frame.
        match conn.stream_writable(stream_id, frame_header_len + header_block_len) {
            Ok(true) => (),
            Ok(false) => {
                info!(
                    "{:?} stream {} send frame HEADERS len {} fin {} blocked, capacity {}",
                    conn.trace_id(),
                    stream_id,
                    frame_header_len + header_block_len,
                    fin,
                    conn.stream_capacity(stream_id).unwrap_or(0)
                );

                // Register want write event to quic transport.
                let _ = conn.stream_want_write(stream_id, true);

                let stream = self.streams.get_mut(&stream_id).unwrap();
                // If there are not enough capacity to write the header_block fully,
                // buffer it and write it again when the stream has enough capacity.
                // We cache the header_block in http/3 stack, eliminating the need for
                // the upper application to cache it.
                stream.set_header_block(Some((header_block, fin)));

                // Here we return `Http3Error::StreamBlocked` to the upper application,
                // so that the upper application can know that the stream is blocked by
                // flow control, and then the upper application can choose to wait for
                // the stream to be writable or do other appropriate actions.
                return Err(Http3Error::StreamBlocked);
            }
            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.stream_destroy(stream_id);
                }

                return Err(e.into());
            }
        };

        // Write HEADERS frame header.
        bytes.truncate(frame_header_len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;
        // Write HEADERS frame payload.
        conn.stream_write(stream_id, header_block, fin)?;

        trace!(
            "{:?} stream {} send frame HEADERS len {} fin {}",
            conn.trace_id(),
            stream_id,
            header_block_len,
            fin
        );

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Current headers have been written to quic stream buffer,
            // if there is cached header_block, we should remove it.
            let _ = stream.take_header_block();

            // Mark stream has been initialized locally.
            stream.mark_local_initialized();

            if fin {
                stream.mark_write_finished();
            }
        }

        // All sending data has been written to quic stream buffer and all incoming data has been read,
        // so we can remove the stream from streams map immediately.
        if fin && conn.stream_finished(stream_id) {
            self.stream_destroy(stream_id);
        }

        Ok(())
    }

    /// Write HTTP/3 headers to quic stream buffer.
    pub fn send_headers<T: NameValue>(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        headers: &[T],
        fin: bool,
    ) -> Result<()> {
        if !stream_id.is_multiple_of(4) || !self.streams.contains_key(&stream_id) {
            return Err(Http3Error::FrameUnexpected);
        }

        let stream = self.streams.get_mut(&stream_id).unwrap();
        if !stream.priority_initialized() {
            let priority = Http3Priority::default();
            conn.stream_set_priority(stream_id, priority.map_to_quic(), priority.incremental)?;
            stream.mark_priority_initialized();
        }

        let header_block = self.encode_header_fields(headers)?;
        self.send_header_block(conn, stream_id, header_block, fin)
    }

    /// Write request or response body into quic transport stream's send buffer.
    pub fn send_body(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        mut body: Bytes,
        mut fin: bool,
    ) -> Result<usize> {
        // Only support sending body on request stream.
        if !stream_id.is_multiple_of(4) {
            return Err(Http3Error::FrameUnexpected);
        }

        // If stream doesn't exist, return `Http3Error::FrameUnexpected`.
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Http3Error::FrameUnexpected)?;

        if let Some((header_block, write_fin)) = stream.take_header_block() {
            // We should update fin flag if the application send empty body with fin.
            let write_fin = write_fin || (fin && body.is_empty());
            self.send_header_block(conn, stream_id, header_block, write_fin)?;

            // Here we return `Http3Error::NoError` to the upper application,
            // so that the upper application can know that the header_block has
            // been sent successfully, and then the upper application can choose
            // to send body or do other appropriate actions.
            return Err(Http3Error::NoError);
        }

        // Stream may be removed while send header_block.
        if !self
            .streams
            .get(&stream_id)
            .ok_or(Http3Error::FrameUnexpected)?
            .local_initialized()
        {
            // Stream header has not been sent yet, should not send body now.
            return Err(Http3Error::FrameUnexpected);
        }

        // Do nothing if the body is empty and the fin flag is false.
        if body.is_empty() && !fin {
            return Err(Http3Error::Done);
        }

        let send_capacity = match conn.stream_capacity(stream_id) {
            Ok(v) => v,
            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.stream_destroy(stream_id);
                }

                return Err(e.into());
            }
        };

        // Here, 1 == codec::encode_varint_len(DATA_FRAME_TYPE).
        let overhead = 1 + codec::encode_varint_len(body.len() as u64);

        // If there is not enough capacity, update writable threshold by `stream_writable`.
        if send_capacity < overhead {
            let _ = conn.stream_writable(stream_id, overhead + 1);

            // Register want write event to quic transport.
            let _ = conn.stream_want_write(stream_id, true);
            return Err(Http3Error::Done);
        }

        // Restrict the frame payload length to the stream's capacity.
        let body_len = body.len();
        let frame_len = std::cmp::min(body_len, send_capacity - overhead);

        // If we can not write all data to quic stream buffer, truncate the body to the stream's capacity,
        // and set the fin flag to false.
        if frame_len < body_len {
            body.truncate(frame_len);
            fin = false;
        }

        // Do nothing if the body is empty and the fin flag is false.
        if body.is_empty() && !fin {
            return Err(Http3Error::Done);
        }

        // DATA_FRAME_TYPE(1Bytes) + data_payload_len(1~8Bytes) <= 9Bytes.
        let mut bytes = BytesMut::zeroed(10);
        let mut b = bytes.as_mut();

        // Write the DATA frame header.
        let mut len = b.write_varint(frame::DATA_FRAME_TYPE)?;
        len += b.write_varint(frame_len as u64)?;
        bytes.truncate(len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;
        // Write the DATA frame payload.
        let written = conn.stream_write(stream_id, body, fin)?;

        trace!(
            "{:?} stream {} send DATA frame written {} body_len {} fin {}",
            conn.trace_id(),
            stream_id,
            written,
            body_len,
            fin
        );

        if written < body_len {
            // After writing partial data, we may not require as much `overhead` capacity
            // and need to update the write threshold, try to notify remote endpoint that
            // the stream is blocked by flow control.
            // Here, 2 == codec::encode_varint_len(DATA_FRAME_TYPE) + 1, where 1 means at
            // least 1 byte of data can be written.
            let write_thresh = 2 + codec::encode_varint_len((body_len - written) as u64);
            let _ = conn.stream_writable(stream_id, write_thresh);

            // Register want write event to quic transport.
            let _ = conn.stream_want_write(stream_id, true);
        } else if fin {
            if conn.stream_finished(stream_id) {
                self.stream_destroy(stream_id);
            } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                // If all data with fin flag has been written to quic stream buffer,
                // but the stream is not completed, mark it as write finished.
                stream.mark_write_finished();
            }
        }

        // Return the number of bytes written to the stream, the frame header is not included.
        Ok(written)
    }

    /// Read request or response body into the given buffer from quic transport stream.
    pub fn recv_body(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut total_read = 0;

        // Attempt to read all buffered data in the QUIC transport stream buffer, even if it spans
        // across multiple HTTP/3 DATA frames.
        while total_read < out.len() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Http3Error::Done)?;

            if stream.state() != Http3StreamState::Data {
                break;
            }

            let (read, fin) = match stream.read_data_from_quic(conn, &mut out[total_read..]) {
                Ok(v) => v,
                Err(Http3Error::Done) => break,
                Err(e) => return Err(e),
            };

            total_read += read;

            // No more data can be read.
            if read == 0 || fin {
                break;
            }

            // Try to process incoming data from the quic stream.
            match self.process_readable_request_stream(conn, stream_id, false) {
                // DATA event must not be triggered when not polling.
                Ok(_) => unreachable!(),
                Err(Http3Error::Done) => (),
                Err(e) => return Err(e),
            };

            // The stream's final size is known and we have read all data from transport.
            if conn.stream_finished(stream_id) {
                break;
            }
        }

        // All incoming data has been read by application, and the stream's final size is known,
        // mark the stream as finished.
        if conn.stream_finished(stream_id) {
            self.process_finished_stream(stream_id);
        }

        if total_read == 0 {
            return Err(Http3Error::Done);
        }

        Ok(total_read)
    }

    /// Send PRIORITY_UPDATE on the control stream with specified request stream ID and priority.
    ///
    /// If the underlying QUIC stream doesn't have enough capacity for the operation to complete,
    /// return [`Http3Error::StreamBlocked`] error. The application should retry the operation once
    /// the stream is reported as writable again.
    pub fn send_priority_update_for_request(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        priority: &Http3Priority,
    ) -> Result<()> {
        // The PRIORITY_UPDATE frame MUST be sent on the client control stream.
        if self.local_control_stream_id.is_none() {
            return Err(Http3Error::FrameUnexpected);
        }

        // The stream has been closed, we should not send PRIORITY_UPDATE frame for it.
        if conn.get_streams().is_closed(stream_id) {
            return Err(Http3Error::FrameUnexpected);
        }

        // RFC9218 7.2. HTTP/3 PRIORITY_UPDATE Frame
        // The request-stream variant of PRIORITY_UPDATE (type=0xF0700) MUST reference
        // a request stream. If a server receives a PRIORITY_UPDATE (type=0xF0700) for
        // a stream ID that is not a request stream, this MUST be treated as a connection
        // error of type H3_ID_ERROR. The stream ID MUST be within the client-initiated
        // bidirectional stream limit. If a server receives a PRIORITY_UPDATE (type=0xF0700)
        // with a stream ID that is beyond the stream limits, this SHOULD be treated as
        // a connection error of type H3_ID_ERROR.
        if !stream_id.is_multiple_of(4) || stream_id > conn.get_streams().peer_max_streams(true) {
            return Err(Http3Error::IdError);
        }

        let urgency = priority.subject_to_bound();
        let mut field_value = format!("u={urgency}");
        if priority.incremental {
            field_value.push_str(",i");
        }

        let priority_field_value = field_value.into_bytes();
        let frame_payload_len = codec::encode_varint_len(stream_id) + priority_field_value.len();

        // Here, 4 == codec::encode_varint_len(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE)
        let overhead = 4
            + codec::encode_varint_len(stream_id)
            + codec::encode_varint_len(frame_payload_len as u64);

        let local_control_stream_id = self.local_control_stream_id.unwrap();

        // Make sure the control stream has enough capacity.
        match conn.stream_writable(
            local_control_stream_id,
            overhead + priority_field_value.len(),
        ) {
            Ok(true) => (),
            Ok(false) => {
                // Register want write event to quic transport.
                let _ = conn.stream_want_write(local_control_stream_id, true);
                return Err(Http3Error::StreamBlocked);
            }
            Err(e) => {
                return Err(e.into());
            }
        }

        trace!(
            "{:?} send frame PRIORITY_UPDATE for request {} with priority_field_value {:?}",
            conn.trace_id(),
            stream_id,
            priority_field_value,
        );

        let mut bytes = BytesMut::zeroed(overhead + priority_field_value.len());
        let frame = frame::Http3Frame::PriorityUpdateRequest {
            prioritized_element_id: stream_id,
            priority_field_value,
        };

        let frame_len = frame.encode(bytes.as_mut())?;
        bytes.truncate(frame_len);
        conn.stream_write(local_control_stream_id, bytes.freeze(), false)?;

        Ok(())
    }

    /// Take the last PRIORITY_UPDATE for the specified prioritized element ID.
    pub fn take_priority_update(&mut self, prioritized_element_id: u64) -> Result<Vec<u8>> {
        match self.streams.get_mut(&prioritized_element_id) {
            Some(stream) => stream.take_priority_update().ok_or(Http3Error::Done),
            None => Err(Http3Error::Done),
        }
    }

    /// Send GOAWAY frame with the given stream ID to close the connection gracefully.
    pub fn send_goaway(&mut self, conn: &mut Connection, id: u64) -> Result<()> {
        if let Some(prev_goaway_id) = self.local_goaway_id {
            // An endpoint MAY send multiple GOAWAY frames indicating different identifiers,
            // but the identifier in each frame MUST NOT be greater than the identifier in
            // any previous frame, since clients might already have retried unprocessed requests
            // on another HTTP connection.
            if id > prev_goaway_id {
                return Err(Http3Error::IdError);
            }
        }

        // The GOAWAY frame is always sent on the control stream.
        // If the control stream is not available, return an error.
        if let Some(stream_id) = self.local_control_stream_id {
            // GOAWAY_FRAME_TYPE(1Bytes) + goaway_id encoded len(1Bytes) + goaway_id(1~8Bytes) <= 10Bytes.
            let mut bytes = BytesMut::zeroed(10);

            let frame = frame::Http3Frame::GoAway { id };
            let frame_len = frame.encode(bytes.as_mut())?;

            let stream_cap = conn.stream_capacity(stream_id)?;
            if stream_cap < frame_len {
                // Register want write event to quic transport.
                let _ = conn.stream_want_write(stream_id, true);
                return Err(Http3Error::StreamBlocked);
            }

            trace!("{:?} send GOAWAY frame {:?}", conn.trace_id(), frame);

            bytes.truncate(frame_len);
            conn.stream_write(stream_id, bytes.freeze(), false)?;

            self.local_goaway_id = Some(id);
            Ok(())
        } else {
            Err(Http3Error::InternalError)
        }
    }

    /// Return the raw settings received from the peer.
    pub fn peer_raw_settings(&self) -> Option<&[(u64, u64)]> {
        self.peer_settings.raw.as_deref()
    }

    /// Get the default priority for the given unidirectional stream type.
    fn uni_stream_default_priority(stream_type: u64) -> (u8, bool) {
        match stream_type {
            // Control and QPACK streams are critical to the operation of HTTP/3,
            // so they are given the highest priority for scheduling.
            stream::HTTP3_CONTROL_STREAM_TYPE
            | stream::QPACK_ENCODER_STREAM_TYPE
            | stream::QPACK_DECODER_STREAM_TYPE => (0, false),

            // Default priority(3 + 124) for push streams.
            stream::HTTP3_PUSH_STREAM_TYPE => (127, true),

            // Other streams are scheduled with the lowest priority.
            // Note that we only support control, QPACK encoder/decoder and push streams for now.
            _ => (255, false),
        }
    }

    /// Open a new unidirectional stream.
    fn open_uni_stream(&mut self, conn: &mut Connection, stream_type: u64) -> Result<u64> {
        let stream_id = self.next_uni_stream_id;

        let (urgency, incremental) = Self::uni_stream_default_priority(stream_type);

        // Note that `StreamLimitError` will be returned if the HTTP/3 critical
        // stream cannot be created due to the concurrency control limit.
        conn.stream_new(stream_id, urgency, incremental)?;

        // Uni stream_type encoded len(1~8Bytes).
        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        // Write the stream type to the quic stream send buffer.
        let len = b.write_varint(stream_type)?;
        bytes.truncate(len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;

        // In order to ensure that stream IDs are not skipped, we calculate the next
        // available stream ID only after data has been successfully buffered.
        self.update_next_uni_stream_id()?;

        Ok(stream_id)
    }

    /// Open QPACK encoder stream.
    fn open_qpack_encoder_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = self.open_uni_stream(conn, stream::QPACK_ENCODER_STREAM_TYPE)?;

        // Record the stream ID of the local QPACK encoder stream.
        self.local_qpack_streams.encoder_stream_id = Some(stream_id);

        Ok(())
    }

    /// Open QPACK decoder stream.
    fn open_qpack_decoder_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = self.open_uni_stream(conn, stream::QPACK_DECODER_STREAM_TYPE)?;

        // Record the stream ID of the local QPACK decoder stream.
        self.local_qpack_streams.decoder_stream_id = Some(stream_id);

        Ok(())
    }

    /// Send SETTINGS frame to peer.
    fn send_settings_frame(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        let frame = frame::Http3Frame::Settings {
            max_field_section_size: self.local_settings.max_field_section_size,
            qpack_max_table_capacity: self.local_settings.qpack_max_table_capacity,
            qpack_blocked_streams: self.local_settings.qpack_blocked_streams,
            connect_protocol_enabled: self.local_settings.connect_protocol_enabled,
            raw: Default::default(),
        };

        let mut bytes = BytesMut::zeroed(128);
        let frame_len = frame.encode(bytes.as_mut())?;
        bytes.truncate(frame_len);
        // RFC9114: Because the contents of the control stream are used to manage the behavior of other streams,
        // endpoints SHOULD provide enough flow-control credit to keep the peer's control stream from becoming blocked.
        conn.stream_write(stream_id, bytes.freeze(), false)?;

        trace!(
            "{:?} send SETTINGS frame on stream {} len {}",
            conn.trace_id(),
            stream_id,
            frame_len
        );

        Ok(())
    }

    /// Open control stream and send SETTINGS frame based on the HTTP/3 configuration.
    fn open_control_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = match self.open_uni_stream(conn, stream::HTTP3_CONTROL_STREAM_TYPE) {
            Ok(v) => v,
            Err(e) => {
                error!("{:?} open control stream failed: {:?}", conn.trace_id(), e);

                if e == Http3Error::Done {
                    return Err(Http3Error::InternalError);
                }

                return Err(e);
            }
        };

        // Record the stream ID of the local control stream.
        self.local_control_stream_id = Some(stream_id);

        // Send SETTINGS frame to peer.
        self.send_settings_frame(conn, stream_id)?;

        Ok(())
    }

    /// Open critical streams, including control, QPACK encoder and decoder streams.
    fn open_critical_streams(&mut self, conn: &mut Connection) -> Result<()> {
        // RFC9114 6.2. Unidirectional Streams
        // Each endpoint needs to create at least one unidirectional stream for the HTTP control stream.
        // QPACK requires two additional unidirectional streams, and other extensions might require
        // further streams. Therefore, the transport parameters sent by both clients and servers MUST
        // allow the peer to create at least three unidirectional streams. These transport parameters
        // SHOULD also provide at least 1,024 bytes of flow-control credit to each unidirectional stream.
        match self.open_control_stream(conn) {
            Ok(_) => (),

            Err(e) => {
                conn.close(true, e.to_wire(), b"open control stream failed")?;
                return Err(e);
            }
        };

        // Try to open QPACK encoder/decoder streams, but ignore errors if it fails
        // since we don't support QPACK dynamic table yet.
        self.open_qpack_encoder_stream(conn).ok();
        self.open_qpack_decoder_stream(conn).ok();

        Ok(())
    }

    /// Register control stream.
    fn register_control_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        // Only one control stream is allowed.
        if self.peer_control_stream_id.is_some() {
            error!(
                "{:?} received multiple control stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9114 6.2.1 Control Streams
            // Only one control stream per peer is permitted; receipt of a
            // second stream claiming to be a control stream MUST be treated
            // as a connection error of type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple control streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's control stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_control_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register QPACK encoder stream.
    fn register_qpack_encoder_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        // Only one QPACK encoder stream is allowed.
        if self.peer_qpack_streams.encoder_stream_id.is_some() {
            error!(
                "{:?} received multiple QPACK encoder stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9204 4.2. Encoder and Decoder Streams
            // Each endpoint MUST initiate, at most, one encoder stream and,
            // at most, one decoder stream. Receipt of a second instance of
            // either stream type MUST be treated as a connection error of
            // type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple QPACK encoder streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's QPACK encoder stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_qpack_streams.encoder_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register QPACK decoder stream.
    fn register_qpack_decoder_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        // Only one QPACK decoder stream is allowed.
        if self.peer_qpack_streams.decoder_stream_id.is_some() {
            error!(
                "{:?} received multiple QPACK decoder stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9204 4.2. Encoder and Decoder Streams
            // Each endpoint MUST initiate, at most, one encoder stream and,
            // at most, one decoder stream. Receipt of a second instance of
            // either stream type MUST be treated as a connection error of
            // type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple QPACK decoder streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's QPACK decoder stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_qpack_streams.decoder_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register critical stream, maybe control, QPACK encoder or decoder stream.
    fn register_critical_stream(
        &mut self,
        conn: &mut Connection,
        stream_type: Http3StreamType,
        stream_id: u64,
    ) -> Result<()> {
        match stream_type {
            Http3StreamType::Control => {
                self.register_control_stream(conn, stream_id)?;
            }
            Http3StreamType::QpackEncoder => {
                self.register_qpack_encoder_stream(conn, stream_id)?;
            }
            Http3StreamType::QpackDecoder => {
                self.register_qpack_decoder_stream(conn, stream_id)?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Receive an HTTP/3 HEADERS frame from the peer.
    fn on_headers_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        field_section: Vec<u8>,
    ) -> Result<(u64, Http3Event)> {
        // RFC9114: The default value of max_field_section_size is unlimited.
        let max_field_section_size = self
            .local_settings
            .max_field_section_size
            .unwrap_or(u64::MAX);

        let headers = match self
            .qpack_decoder
            .decode(&field_section[..], max_field_section_size)
        {
            Ok(v) => v.0,
            Err(e) => {
                error!(
                    "{:?} stream {} qpack decode error: {:?}",
                    conn.trace_id(),
                    stream_id,
                    e
                );

                conn.close(true, e.to_wire(), b"qpack decompression failed")?;
                return Err(e);
            }
        };

        let headers_event = Http3Event::Headers {
            headers,
            fin: conn.stream_finished(stream_id),
        };

        Ok((stream_id, headers_event))
    }

    /// Receive an HTTP/3 DATA frame from the peer.
    fn on_data_frame_received(
        &mut self,
        _conn: &mut Connection,
        _stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Do nothing. The Data event is processed separately.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 GOAWAY frame from the peer.
    fn on_goaway_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        id: u64,
    ) -> Result<(u64, Http3Event)> {
        // RFC9114 7.2.6. GOAWAY
        // In the server-to-client direction, it carries a QUIC stream ID for a client-initiated
        // bidirectional stream encoded as a variable-length integer. A client MUST treat receipt
        // of a GOAWAY frame containing a stream ID of any other type as a connection error of
        // type H3_ID_ERROR.
        if !id.is_multiple_of(4) {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"client received GOAWAY on non-request stream",
            )?;

            return Err(Http3Error::IdError);
        }

        // RFC9114 5.2 Connection Shutdown
        // An endpoint MAY send multiple GOAWAY frames indicating different identifiers,
        // but the identifier in each frame MUST NOT be greater than the identifier in any
        // previous frame, since clients might already have retried unprocessed requests on
        // another HTTP connection. Receiving a GOAWAY containing a larger identifier than
        // previously received MUST be treated as a connection error of type H3_ID_ERROR.
        if let Some(prev_id) = self.peer_goaway_id
            && id > prev_id
        {
            error!(
                "{:?} recv GOAWAY on stream {} carries a larger ID {} than previously received {}",
                conn.trace_id(),
                stream_id,
                id,
                prev_id
            );

            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"GOAWAY carries a larger ID than previously received",
            )?;
            return Err(Http3Error::IdError);
        }

        self.peer_goaway_id = Some(id);
        Ok((id, Http3Event::GoAway))
    }

    /// Receive an HTTP/3 MAX_PUSH_ID frame from the peer.
    fn on_max_push_id_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        conn.close(
            true,
            Http3Error::FrameUnexpected.to_wire(),
            b"MAX_PUSH_ID received by client",
        )?;

        Err(Http3Error::FrameUnexpected)
    }

    /// Receive an HTTP/3 PUSH_PROMISE frame from the peer.
    fn on_push_promise_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        push_id: u64,
        _field_section: Vec<u8>,
    ) -> Result<(u64, Http3Event)> {
        // The PUSH_PROMISE frame (type=0x05) is used to carry a promised request header section
        // from server to client on a request stream.
        if !stream_id.is_multiple_of(4) {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"PUSH_PROMISE received on non-request stream",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // A server MUST NOT use a push ID that is larger than the client has provided in a
        // MAX_PUSH_ID frame (Section 7.2.7). A client MUST treat receipt of a PUSH_PROMISE
        // frame that contains a larger push ID than the client has advertised as a connection
        // error of H3_ID_ERROR.
        if Some(push_id) > self.max_push_id {
            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"PUSH_PROMISE uses a larger push ID than the client has advertised",
            )?;

            return Err(Http3Error::IdError);
        }

        // Ignore the PUSH_PROMISE field_section temporarily.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 CANCEL_PUSH frame from the peer.
    fn on_cancel_push_frame_received(
        &mut self,
        _conn: &mut Connection,
        _stream_id: u64,
        _push_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Ignore CANCEL_PUSH frame temporarily.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 PRIORITY_UPDATE frame for request stream from the peer.
    fn on_priority_update_request_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        conn.close(
            true,
            Http3Error::FrameUnexpected.to_wire(),
            b"client received PRIORITY_UPDATE",
        )?;

        Err(Http3Error::FrameUnexpected)
    }

    /// Receive an HTTP/3 PRIORITY_UPDATE frame for push stream from the peer.
    fn on_priority_update_push_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
        _prioritized_element_id: u64,
    ) -> Result<(u64, Http3Event)> {
        conn.close(
            true,
            Http3Error::FrameUnexpected.to_wire(),
            b"client received PRIORITY_UPDATE",
        )?;

        Err(Http3Error::FrameUnexpected)
    }

    /// Process an HTTP/3 frame received from the peer.
    fn process_frame(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        frame: frame::Http3Frame,
        payload_len: u64,
    ) -> Result<(u64, Http3Event)> {
        trace!(
            "{:?} stream {} recv frame {:?}, payload_len={}",
            conn.trace_id(),
            stream_id,
            frame,
            payload_len
        );

        match frame {
            frame::Http3Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                raw,
                ..
            } => {
                self.peer_settings = Http3Settings {
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                    connect_protocol_enabled,
                    raw,
                };
            }

            frame::Http3Frame::Headers { field_section } => {
                return self.on_headers_frame_received(conn, stream_id, field_section);
            }

            frame::Http3Frame::Data { .. } => {
                return self.on_data_frame_received(conn, stream_id);
            }

            frame::Http3Frame::GoAway { id } => {
                return self.on_goaway_frame_received(conn, stream_id, id);
            }

            frame::Http3Frame::MaxPushId { .. } => {
                return self.on_max_push_id_frame_received(conn, stream_id);
            }

            frame::Http3Frame::PushPromise {
                push_id,
                field_section,
            } => {
                return self.on_push_promise_frame_received(
                    conn,
                    stream_id,
                    push_id,
                    field_section,
                );
            }

            frame::Http3Frame::CancelPush { push_id } => {
                return self.on_cancel_push_frame_received(conn, stream_id, push_id);
            }

            frame::Http3Frame::PriorityUpdateRequest { .. } => {
                return self.on_priority_update_request_frame_received(conn, stream_id);
            }

            frame::Http3Frame::PriorityUpdatePush {
                prioritized_element_id,
                ..
            } => {
                return self.on_priority_update_push_frame_received(
                    conn,
                    stream_id,
                    prioritized_element_id,
                );
            }

            frame::Http3Frame::Unknown { .. } => (),
        }

        Err(Http3Error::Done)
    }

    /// Process readable QPACK encoder/decoder stream.
    fn process_readable_qpack_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        let mut d: [u8; 4096] = unsafe {
            #[allow(clippy::uninit_assumed_init, invalid_value)]
            MaybeUninit::uninit().assume_init()
        };

        // We don't support qpack dynamic table yet, so just read and discard all data.
        loop {
            conn.stream_read(stream_id, &mut d)?;
        }
    }

    /// Process readable HTTP/3 push stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_push_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::PushId => {
                    stream.parse_push_id(conn)?;
                }

                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    // For application-layer initiated streams with frame data, events are reported
                    // only when polling.
                    if !polling {
                        break;
                    }

                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there may be more data in the stream to process.
                        Err(Http3Error::Done) => {
                            // If the stream is finished, return early to avoid trying to read again on a closed stream.
                            if conn.stream_finished(stream_id) {
                                break;
                            }
                        }
                        Err(e) => return Err(e),
                    };
                }

                Http3StreamState::Data => {
                    // 1. If not polling, we don't need to trigger events.
                    // 2. If polling, we don't need to trigger events repeatedly during one poll.
                    if !polling || !stream.trigger_data_event() {
                        break;
                    }
                    return Ok((stream_id, Http3Event::Data));
                }

                Http3StreamState::ReadFinished => break,

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process readable HTTP/3 control stream.
    fn process_readable_control_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there may be more data in the stream to process.
                        Err(Http3Error::Done) => (),
                        Err(e) => return Err(e),
                    };
                }

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process a new unidirectional stream.
    fn process_new_uni_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        stream_type: Http3StreamType,
    ) -> Result<()> {
        match stream_type {
            Http3StreamType::Control
            | Http3StreamType::QpackEncoder
            | Http3StreamType::QpackDecoder => {
                // Register critical stream to HTTP/3 connection.
                self.register_critical_stream(conn, stream_type, stream_id)?;
            }

            Http3StreamType::Unknown(type_id) => {
                error!(
                    "{:?} received unknown type {} stream {}",
                    conn.trace_id(),
                    type_id,
                    stream_id
                );
                // Unknown stream types, ignore it and shutdown the stream in the outer logic.
            }

            // Request stream always a bididirectional stream, so it won't reach here.
            Http3StreamType::Request => unreachable!(),

            Http3StreamType::Push => unreachable!(),
        }

        Ok(())
    }

    /// Process readable unidirectional stream, maybe control, push or QPACK encoder/decoder stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_uni_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => return Err(Http3Error::Done),
        };

        // Stream's type still unknown, try to parse it first.
        if stream.state() == Http3StreamState::StreamType {
            let stream_type = stream.parse_uni_stream_type(conn)?;
            self.process_new_uni_stream(conn, stream_id, stream_type)?;
        }

        let stream = self.streams.get(&stream_id).unwrap();
        match stream.stream_type().unwrap() {
            Http3StreamType::Control => {
                return self.process_readable_control_stream(conn, stream_id);
            }

            Http3StreamType::Push => {
                return self.process_readable_push_stream(conn, stream_id, polling);
            }

            // Actually, Encoder and Decoder have different parsing instruction formats,
            // but since we don't support dynamic table, we handle them here.
            Http3StreamType::QpackEncoder | Http3StreamType::QpackDecoder => {
                return self.process_readable_qpack_stream(conn, stream_id);
            }

            Http3StreamType::Unknown(_) => {
                // Unknown stream types, ignore it and shutdown stream with H3_NO_ERROR(0x100).
                conn.stream_shutdown(stream_id, crate::Shutdown::Read, 0x100)?;
            }

            Http3StreamType::Request => unreachable!(),
        }

        Err(Http3Error::Done)
    }

    /// Process a readable HTTP/3 request stream, which is alaways a bididirectional stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_request_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    // Only trigger events when polling is true.
                    if !polling {
                        break;
                    }

                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there
                        // may still be more data in the stream to process.
                        Err(Http3Error::Done) => {
                            // If the stream is finished, return early to avoid
                            // attempting to read again on a finished stream.
                            if conn.stream_finished(stream_id) {
                                break;
                            }
                        }
                        Err(e) => return Err(e),
                    };
                }

                Http3StreamState::Data => {
                    // Only trigger Data event when polling is true and the Data event
                    // has not been triggered in current poll.
                    if !polling || !stream.trigger_data_event() {
                        break;
                    }
                    return Ok((stream_id, Http3Event::Data));
                }

                Http3StreamState::ReadFinished => break,

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process a readable HTTP/3 stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // If the stream doesn't exist, try to create it.
        if let Err(e) = self.get_or_create(stream_id, false) {
            trace!(
                "{:?} get_or_create stream {} failed, error: {:?}",
                conn.trace_id(),
                stream_id,
                e
            );
            conn.close(true, e.to_wire(), b"")?;
            return Err(e);
        };

        match crate::stream::is_bidi(stream_id) {
            false => self.process_readable_uni_stream(conn, stream_id, polling),
            true => self.process_readable_request_stream(conn, stream_id, polling),
        }
    }

    /// Mark a request or push stream as finished, and add it to the list of finished streams.
    fn process_finished_stream(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.state() == Http3StreamState::ReadFinished {
                return;
            }

            match stream.stream_type() {
                Some(Http3StreamType::Request) | Some(Http3StreamType::Push) => {
                    stream.mark_read_finished();
                    self.finished_streams.push_back(stream_id);
                }
                _ => (),
            };
        }
    }

    /// Check if the critical stream is in an open state.
    fn check_critical_stream_state(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        // Critical streams MUST NOT be closed.
        //
        // RFC9114 6.2.1. Control Streams
        // If either control stream is closed at any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.
        //
        // RFC9204 4.2. Encoder and Decoder Streams
        // The sender MUST NOT close either of these streams, and the receiver MUST NOT request that the sender close either of these streams.
        // Closure of either unidirectional stream type MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.
        if conn.stream_finished(stream_id) {
            error!("{:?} critical stream {} closed", conn.trace_id(), stream_id);

            conn.close(
                true,
                Http3Error::ClosedCriticalStream.to_wire(),
                b"closed critical stream",
            )?;

            return Err(Http3Error::ClosedCriticalStream);
        }

        Ok(())
    }

    /// Process critical stream, maybe control, QPACK encoder or decoder stream.
    fn process_critical_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        self.check_critical_stream_state(conn, stream_id)?;

        if !conn.stream_readable(stream_id) {
            return Err(Http3Error::Done);
        }

        match self.process_readable_uni_stream(conn, stream_id, true) {
            Ok(ev) => return Ok(ev),
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        };

        self.check_critical_stream_state(conn, stream_id)?;

        Err(Http3Error::Done)
    }

    /// Process known critical streams, including HTTP/3 control, QPACK encoder/decoder streams.
    fn process_critical_streams(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        // Note that HTTP/3 control stream should be processed first.
        for &stream_id in &[
            self.peer_control_stream_id,
            self.peer_qpack_streams.encoder_stream_id,
            self.peer_qpack_streams.decoder_stream_id,
        ] {
            if let Some(s) = stream_id {
                match self.process_critical_stream(conn, s) {
                    Ok(ev) => return Ok(ev),
                    // Everything is fine, continue.
                    Err(Http3Error::Done) => (),
                    Err(e) => return Err(e),
                }
            }
        }

        Err(Http3Error::Done)
    }

    // Process all readable HTTP/3 streams.
    fn process_readable_streams(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        for stream_id in conn.stream_readable_iter() {
            trace!("{:?} stream {} readable", conn.trace_id(), stream_id);

            let ev = match self.process_readable_stream(conn, stream_id, true) {
                Ok(v) => Some(v),
                // May have received an empty FIN.
                Err(Http3Error::Done) => None,
                // If the stream was reset, return a Reset event early, to avoid return a Finished event later.
                Err(Http3Error::TransportError(crate::Error::StreamReset(e))) => {
                    return Ok((stream_id, Http3Event::Reset(e)));
                }
                Err(e) => return Err(e),
            };

            if conn.stream_finished(stream_id) {
                trace!("{:?} stream {} finished", conn.trace_id(), stream_id);
                self.process_finished_stream(stream_id);

                // If the HTTP/3 stream has been finished for both reading and writing, we can remove it immediately.
                if let Some(stream) = self.streams.get_mut(&stream_id)
                    && stream.write_finished()
                {
                    trace!("{:?} stream {} completed", conn.trace_id(), stream_id);
                    self.stream_destroy(stream_id);
                }
            }

            if let Some(ev) = ev {
                return Ok(ev);
            }
        }

        Err(Http3Error::Done)
    }

    /// Process HTTP/3 streams data and trigger events.
    ///
    /// On success, it returns a stream ID and an Http3Event, or Http3Error::Done when there
    /// are no events need to be report. On error, it returns an Http3Error.
    ///
    /// Note that all HTTP/3 events are edge-triggered, which means that applications will
    /// not receive the same event twice unless the event is re-armed.
    ///
    /// QUIC connection will be closed with the appropriate error code if an error occurs
    /// while processing HTTP/3 streams data.
    pub fn poll(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        // The underlying quic transport connection has been in a broken state, return early.
        if conn.local_error().is_some() {
            return Err(Http3Error::Done);
        }

        // Process finished HTTP/3 streams.
        if let Some(stream_id) = self.finished_streams.pop_front() {
            return Ok((stream_id, Http3Event::Finished));
        }

        // Process known critical streams, including HTTP/3 control, QPACK encoder/decoder streams.
        match self.process_critical_streams(conn) {
            Ok(ev) => return Ok(ev),
            // Everything is fine, continue.
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        }

        // Process all readable HTTP/3 streams.
        match self.process_readable_streams(conn) {
            Ok(ev) => return Ok(ev),
            // Everything is fine, continue.
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        }

        // Note that when receiving empty stream frames with the fin flag set,
        // we would not get an event from process_readable_streams, but it may
        // finished, we should return a `Finished` event.
        if let Some(stream_id) = self.finished_streams.pop_front() {
            return Ok((stream_id, Http3Event::Finished));
        }

        Err(Http3Error::Done)
    }

    /// Process internal events of all HTTP/3 streams on the connection.
    pub fn process_streams(&mut self, conn: &mut Connection) -> Result<()> {
        trace!("{:?} process streams", conn.trace_id());

        // Handler is not set, return early.
        if self.handler.is_none() {
            return Ok(());
        }

        // Note that we can not save handler before poll, otherwise the handler will be borrowed twice.
        loop {
            match self.poll(conn) {
                Ok((stream_id, Http3Event::Headers { headers, fin })) => {
                    self.handler
                        .as_ref()
                        .unwrap()
                        .on_stream_headers(stream_id, &mut Http3Event::Headers { headers, fin });
                }

                Ok((stream_id, Http3Event::Data)) => {
                    self.handler.as_ref().unwrap().on_stream_data(stream_id);
                }

                Ok((stream_id, Http3Event::Finished)) => {
                    self.handler.as_ref().unwrap().on_stream_finished(stream_id);
                }

                Ok((stream_id, Http3Event::Reset(e))) => {
                    self.handler.as_ref().unwrap().on_stream_reset(stream_id, e);
                }

                Ok((stream_id, Http3Event::PriorityUpdate)) => {
                    self.handler
                        .as_ref()
                        .unwrap()
                        .on_stream_priority_update(stream_id);
                }

                Ok((stream_id, Http3Event::GoAway)) => {
                    self.handler.as_ref().unwrap().on_conn_goaway(stream_id);
                }

                Err(Http3Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("{:?} process HTTP/3 streams error {:?}", conn.trace_id(), e);
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// An HTTP/3 settings.
struct Http3Settings {
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub connect_protocol_enabled: Option<u64>,
    pub raw: Option<Vec<(u64, u64)>>,
}

/// An endpoint's QPACK streams.
struct QpackStreams {
    pub encoder_stream_id: Option<u64>,
    pub decoder_stream_id: Option<u64>,
}

/// An extensible HTTP/3 Priority Parameters
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Http3Priority {
    pub urgency: u8,
    pub incremental: bool,
}

impl Default for Http3Priority {
    /// Create a new Http3Priority with default urgency and incremental.
    fn default() -> Self {
        Http3Priority {
            urgency: PRIORITY_URGENCY_DEFAULT,
            incremental: PRIORITY_INCREMENTAL_DEFAULT,
        }
    }
}

impl Http3Priority {
    /// Create a new Http3Priority with the given urgency and incremental.
    pub const fn new(urgency: u8, incremental: bool) -> Self {
        Http3Priority {
            urgency,
            incremental,
        }
    }

    /// HTTP/3 priority urgency subject to protocol bound.
    fn subject_to_bound(&self) -> u8 {
        self.urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND)
    }

    /// Map HTTP/3 urgency to QUIC urgency.
    fn map_to_quic(&self) -> u8 {
        self.subject_to_bound() + PRIORITY_URGENCY_OFFSET
    }
}

impl TryFrom<&[u8]> for Http3Priority {
    type Error = crate::h3::Http3Error;

    /// Try to parse an Priority field value, which was encoded as a Dictionary.
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let dict = match sfv::Parser::new(value).parse::<sfv::Dictionary>() {
            Ok(v) => v,
            Err(_) => return Err(Http3Error::Done),
        };

        let urgency = match dict.get("u") {
            Some(sfv::ListEntry::Item(item)) => match item.bare_item.as_integer() {
                Some(v) => {
                    if (PRIORITY_URGENCY_LOWER_BOUND as i64..=PRIORITY_URGENCY_UPPER_BOUND as i64)
                        .contains(&v.into())
                    {
                        Into::<i64>::into(v) as u8
                    } else {
                        PRIORITY_URGENCY_UPPER_BOUND
                    }
                }

                None => return Err(Http3Error::Done),
            },

            // Priority urgency must be an Integer, but not a List.
            Some(sfv::ListEntry::InnerList(_)) => return Err(Http3Error::Done),

            // Priority urgency parameter not found, use default value.
            None => PRIORITY_URGENCY_DEFAULT,
        };

        let incremental = match dict.get("i") {
            // Priority incremental must be a Boolean.
            Some(sfv::ListEntry::Item(item)) => {
                item.bare_item.as_boolean().ok_or(Http3Error::Done)?
            }

            // Priority incremental must be an Boolean, but not a List.
            Some(sfv::ListEntry::InnerList(_)) => return Err(Http3Error::Done),

            // Priority incremental parameter not found, use default value.
            None => PRIORITY_INCREMENTAL_DEFAULT,
        };

        Ok(Http3Priority::new(urgency, incremental))
    }
}
