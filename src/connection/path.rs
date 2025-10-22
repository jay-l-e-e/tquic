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

use std::any::Any;
use std::cmp;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;
use std::time::Duration;
use std::time::Instant;

use slab::Slab;

use super::pmtu::Dplpmtud;
use super::recovery::Recovery;
use super::timer;
use crate::FourTuple;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::TIMER_GRANULARITY;
use crate::connection::SpaceId;
use crate::error::Error;
use crate::multipath_scheduler::MultipathScheduler;

pub(crate) const INITIAL_CHAL_TIMEOUT: u64 = 25;

pub(crate) const MAX_PROBING_TIMEOUTS: usize = 8;

pub(crate) const MAX_PATH_CHALS_RECV: usize = 8;

pub(crate) const MIN_PATH_PROBE_SIZE: usize = 64;

/// A network path on which QUIC packets can be sent.
pub struct Path {
    /// The local address.
    local_addr: SocketAddr,

    /// The remote address.
    remote_addr: SocketAddr,

    /// Source CID sequence number used over that path.
    pub(crate) scid_seq: Option<u64>,

    /// Destination CID sequence number used over that path.
    pub(crate) dcid_seq: Option<u64>,

    /// Peer context for the path.
    pub(crate) peer_context: Option<Box<dyn Any + Send + Sync>>,

    /// Is this path used to send non-probing packets. By default, the initial
    /// path is active and the others are not active.
    active: bool,

    /// Loss recovery and congestion control.
    pub(crate) recovery: Recovery,

    /// The current validation state of the path.
    state: PathState,

    /// Received path challenge data.
    recv_chals: VecDeque<[u8; 8]>,

    /// Pending challenge data with the size of the packet containing them.
    sent_chals: VecDeque<([u8; 8], usize, time::Instant, time::Instant)>,

    /// Whether it requires sending PATH_CHALLENGE?
    need_send_challenge: bool,

    /// Number of consecutive path probing packets lost.
    lost_chal: usize,

    /// The maximum challenge size that got acknowledged.
    max_challenge_size: usize,

    /// Whether the peer's address has been verified.
    pub(super) verified_peer_address: bool,

    /// Whether the peer has verified our address.
    pub(super) peer_verified_local_address: bool,

    /// Total bytes the server can send before the client's address is verified.
    pub(super) anti_ampl_limit: usize,

    /// The current pmtu probing state of the path.
    pub(super) dplpmtud: Dplpmtud,

    /// Whether a Ping frame should be sent on the path.
    pub(super) need_send_ping: bool,

    /// Trace id.
    trace_id: String,

    /// Packet number space for current path in MPQUIC mode.
    pub(crate) space_id: SpaceId,

    /// Whether the path has been abandoned in MPQUIC mode.
    pub(super) is_abandon: bool,
}

impl Path {
    /// Create a new path
    pub(crate) fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        is_initial: bool,
        conf: &RecoveryConfig,
        trace_id: &str,
    ) -> Self {
        let (state, scid_seq, dcid_seq) = if is_initial {
            (PathState::Validated, Some(0), Some(0))
        } else {
            (PathState::Unknown, None, None)
        };

        let dplpmtud = Dplpmtud::new(
            conf.enable_dplpmtud,
            conf.max_datagram_size,
            Self::is_ipv6(&remote_addr),
        );

        Self {
            local_addr,
            remote_addr,
            scid_seq,
            dcid_seq,
            peer_context: None,
            active: false,
            recovery: Recovery::new(conf),
            state,
            recv_chals: VecDeque::new(),
            sent_chals: VecDeque::new(),
            need_send_challenge: false,
            lost_chal: 0,
            max_challenge_size: 0,
            verified_peer_address: false,
            peer_verified_local_address: false,
            anti_ampl_limit: 0,
            dplpmtud,
            need_send_ping: false,
            trace_id: trace_id.to_string(),
            space_id: SpaceId::Data,
            is_abandon: false,
        }
    }

    /// Update trace id, appending path id.
    #[doc(hidden)]
    pub fn update_trace_id(&mut self, path_id: usize) {
        self.trace_id.push_str(&(format!("-{}", path_id)));
        self.recovery.set_trace_id(&self.trace_id);
    }

    /// Return the local address of the path.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the remote address of the path.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Handle incoming PATH_CHALLENGE data.
    pub(super) fn on_path_chal_received(&mut self, data: [u8; 8]) {
        if self.recv_chals.len() >= MAX_PATH_CHALS_RECV {
            let _ = self.recv_chals.pop_front();
        }

        self.recv_chals.push_back(data);
        self.peer_verified_local_address = true;
    }

    /// Handle incoming PATH_RESPONSE data.
    /// Return true if the path status changes to `Validated`.
    pub(super) fn on_path_resp_received(&mut self, data: [u8; 8], multipath: bool) -> bool {
        if self.state == PathState::Validated {
            return false;
        }

        self.verified_peer_address = true;
        self.lost_chal = 0;

        // The 4-tuple is reachable, but we didn't check Path MTU yet.
        let mut challenge_size = 0;
        self.sent_chals.retain(|(d, s, sent_time, _)| {
            if *d == data {
                challenge_size = *s;
                // Use the delay between sending a PATH_CHALLENGE and receiving a PATH_RESPONSE
                // to set the initial RTT for the new path. This delay should not be considered
                // an RTT sample.
                let initial_rtt = Instant::now().duration_since(*sent_time);
                self.recovery.rtt.try_set_init_rtt(initial_rtt);
                false
            } else {
                true
            }
        });
        self.max_challenge_size = std::cmp::max(self.max_challenge_size, challenge_size);
        self.promote_to(PathState::ValidatingMTU);

        // The MTU was validated
        if self.max_challenge_size >= crate::MIN_CLIENT_INITIAL_LEN {
            self.promote_to(PathState::Validated);
            self.set_active(multipath);
            self.sent_chals.clear();
            return true;
        }

        // If the MTU was not validated, probe again.
        self.need_send_challenge = true;
        false
    }

    /// Fetch a received challenge data item.
    pub(super) fn pop_recv_chal(&mut self) -> Option<[u8; 8]> {
        self.recv_chals.pop_front()
    }

    /// Return whether path validation has been initialed.
    pub(super) fn path_chal_initiated(&self) -> bool {
        self.need_send_challenge
    }

    /// Request path validation.
    pub(super) fn initiate_path_chal(&mut self) {
        self.need_send_challenge = true;
    }

    /// Handle sent event of PATH_CHALLENGE
    pub(super) fn on_path_chal_sent(
        &mut self,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) {
        self.promote_to(PathState::Validating);
        self.need_send_challenge = false;

        // Use exponential back-off because the RTT of the new path is unknown.
        let loss_time =
            sent_time + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT << self.lost_chal);

        self.sent_chals
            .push_back((data, pkt_size, sent_time, loss_time));
    }

    /// Handle timeout of PATH_CHALLENGE
    pub(super) fn on_path_chal_timeout(&mut self, now: time::Instant) {
        if self.state != PathState::Validating && self.state != PathState::ValidatingMTU {
            return;
        }

        // Remove the lost challenges.
        while let Some(first_chal) = self.sent_chals.front() {
            if first_chal.3 > now {
                return;
            }

            self.sent_chals.pop_front();
            self.lost_chal += 1;

            if self.lost_chal < MAX_PROBING_TIMEOUTS {
                // Try to initiate path validation again.
                self.initiate_path_chal();
            } else {
                // The Path validation eventually failed.
                self.state = PathState::Failed;
                self.active = false;
                self.sent_chals.clear();
                return;
            }
        }
    }

    /// Set peer context
    pub fn set_peer_context<T: Any + Send + Sync>(&mut self, ctx: T) {
        self.peer_context = Some(Box::new(ctx));
    }

    /// Get peer context
    pub fn peer_context(&mut self) -> Option<&mut dyn Any> {
        match self.peer_context {
            Some(ref mut data) => Some(data.as_mut()),
            None => None,
        }
    }

    /// Whether PATH_CHALLENGE or PATH_RESPONSE should be sent on the path.
    pub(super) fn need_send_validation_frames(&self) -> bool {
        self.need_send_challenge || !self.recv_chals.is_empty()
    }

    /// Whether the datagrams sent on the unvalidated path should be expanded
    /// to least the maximum datagram size
    pub(super) fn need_expand_padding_frames(&self) -> bool {
        if self.validated() {
            return false;
        }
        true
    }

    /// Promote the path to the provided state.
    fn promote_to(&mut self, state: PathState) {
        if self.state < state {
            self.state = state;
        }
    }

    /// Return whether the path is validated.
    pub fn validated(&self) -> bool {
        self.state == PathState::Validated
    }

    /// Return whether the path is used to send non-probing packets.
    pub fn active(&self) -> bool {
        self.active && self.dcid_seq.is_some()
    }

    /// Set the active state of the path
    pub(crate) fn set_active(&mut self, v: bool) {
        self.active = v;
    }

    /// Return whether the path is unused.
    fn unused(&self) -> bool {
        !self.active && self.dcid_seq.is_none()
    }

    /// Update and return the latest statistics about the path
    pub fn stats(&mut self) -> &PathStats {
        self.recovery.stat_lazy_update();
        &self.recovery.stats
    }

    /// Return the validation state of the path
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Return true if the given address is a pure IPv6 address, rather than an
    /// IPv4-mapped IPv6 address.
    fn is_ipv6(addr: &SocketAddr) -> bool {
        if let IpAddr::V6(ip) = addr.ip()
            && !matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        {
            return true;
        }
        false
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "local={:?} ", self.local_addr)?;
        write!(f, "remote={:?}", self.remote_addr)?;
        Ok(())
    }
}

/// The states about the path validation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathState {
    /// The path validation failed
    Failed,

    /// No path validation has been performed.
    Unknown,

    /// The path is under validation.
    Validating,

    /// The remote address has been validated, but not the path MTU.
    ValidatingMTU,

    /// The path has been validated.
    Validated,
}

/// Path manager for a QUIC connection
pub(crate) struct PathMap {
    /// The paths of the connection. Each path has a path identifier
    /// used by `addrs`.
    paths: Slab<Path>,

    /// The maximum number of paths allowed.
    max_paths: usize,

    /// The mapping from the (local `SocketAddr`, peer `SocketAddr`) to the
    /// `Path` identifier.
    addrs: BTreeMap<(SocketAddr, SocketAddr), usize>,

    /// The anti-amplification factor.
    pub(crate) anti_ampl_factor: usize,

    /// Whether the multipath extension is successfully negotiated.
    is_multipath: bool,
}

impl PathMap {
    pub fn new(mut initial_path: Path, max_paths: usize, anti_ampl_factor: usize) -> Self {
        // As it is the first path, it is active by default.
        initial_path.active = true;
        let local_addr = initial_path.local_addr;
        let remote_addr = initial_path.remote_addr;

        let mut paths = Slab::with_capacity(2);
        let active_path_id = paths.insert(initial_path);

        if let Some(path) = paths.get_mut(active_path_id) {
            path.update_trace_id(active_path_id);
        }

        let mut addrs = BTreeMap::new();
        addrs.insert((local_addr, remote_addr), active_path_id);

        Self {
            paths,
            max_paths,
            addrs,
            anti_ampl_factor,
            is_multipath: false,
        }
    }

    /// Get an immutable reference to the path identified by `path_id`
    pub fn get(&self, path_id: usize) -> Result<&Path> {
        self.paths.get(path_id).ok_or(Error::InternalError)
    }

    /// Get an mutable reference to the path identified by `path_id`
    pub fn get_mut(&mut self, path_id: usize) -> Result<&mut Path> {
        self.paths.get_mut(path_id).ok_or(Error::InternalError)
    }

    /// Get the `Path` identifier related to the given `addrs`.
    ///
    /// The address tuple `addrs` is (local address, remote address)
    pub fn get_path_id(&self, addrs: &(SocketAddr, SocketAddr)) -> Option<usize> {
        self.addrs.get(addrs).copied()
    }

    /// Get an mutable reference to the active path.
    pub fn get_active(&self) -> Result<&Path> {
        Ok(self.get_active_with_path_id()?.1)
    }

    /// Get an mutable reference to the active path.
    pub fn get_active_mut(&mut self) -> Result<&mut Path> {
        let path = self.paths.iter_mut().find(|(_, p)| p.active);
        Ok(path.ok_or(Error::InternalError)?.1)
    }

    /// Get the `Path` identifier related to the active path.
    pub fn get_active_path_id(&self) -> Result<usize> {
        Ok(self.get_active_with_path_id()?.0)
    }

    /// Get an mutable reference to the active path with the value of the
    /// path identifier. If there is no active path, returns `None`.
    pub fn get_active_with_path_id(&self) -> Result<(usize, &Path)> {
        self.paths
            .iter()
            .find(|(_, p)| p.active)
            .ok_or(Error::InternalError)
    }

    /// Insert a new path
    pub fn insert_path(&mut self, path: Path) -> Result<usize> {
        // eliminate an unused path if the maximum paths limit is reached
        if self.paths.len() >= self.max_paths {
            let (pid_to_remove, _) = self
                .paths
                .iter()
                .find(|(_, p)| p.unused()) // TODO: or failed path ?
                .ok_or(Error::Done)?;
            let path = self.paths.remove(pid_to_remove);
            self.addrs.remove(&(path.local_addr, path.remote_addr));
        }

        // insert new path
        let local_addr = path.local_addr;
        let remote_addr = path.remote_addr;

        let pid = self.paths.insert(path);
        self.addrs.insert((local_addr, remote_addr), pid);
        Ok(pid)
    }

    /// Return an immutable iterator over all existing paths.
    pub fn iter(&self) -> slab::Iter<Path> {
        self.paths.iter()
    }

    /// Return a mutable iterator over all existing paths.
    pub fn iter_mut(&mut self) -> slab::IterMut<Path> {
        self.paths.iter_mut()
    }

    /// Return the number of all paths
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Process a PATH_CHALLENGE frame on the give path
    pub fn on_path_chal_received(&mut self, path_id: usize, data: [u8; 8]) {
        if let Some(path) = self.paths.get_mut(path_id) {
            path.on_path_chal_received(data);
        }
    }

    /// Process a PATH_RESPONSE frame on the give path
    pub fn on_path_resp_received(&mut self, path_id: usize, data: [u8; 8]) -> bool {
        if let Some(path) = self.paths.get_mut(path_id) {
            return path.on_path_resp_received(data, self.is_multipath);
        }
        false
    }

    /// Handle the sent event of PATH_CHALLENGE.
    pub fn on_path_chal_sent(
        &mut self,
        path_id: usize,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) -> Result<()> {
        let path = self.get_mut(path_id)?;
        path.on_path_chal_sent(data, pkt_size, sent_time);

        Ok(())
    }

    /// Handle timeout of PATH_CHALLENGE.
    pub fn on_path_chal_timeout(&mut self, now: time::Instant) {
        for (_, path) in self.paths.iter_mut() {
            path.on_path_chal_timeout(now);
        }
    }

    /// Return the lowest loss timer value among all paths.
    pub fn min_loss_detection_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.recovery.loss_detection_timer())
            .min()
    }

    /// Return the lowest pacer timer value among all paths.
    pub fn min_pacer_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.recovery.pacer_timer)
            .min()
    }

    /// Return the minimum timeout among all paths.
    pub fn min_path_chal_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.sent_chals.front())
            .min_by_key(|&(_, _, _, loss_time)| loss_time)
            .map(|&(_, _, _, loss_time)| loss_time)
    }

    /// Return the maximum PTO among all paths.
    pub fn max_pto(&self) -> Option<Duration> {
        self.iter()
            .map(|(_, path)| path.recovery.rtt.pto_base())
            .max()
    }

    /// Schedule a Ping frame on the specified path or all active paths.
    pub fn mark_ping(&mut self, path_addr: Option<FourTuple>) -> Result<()> {
        // If multipath is not enabled, schedule a Ping frame on the current
        // active path.
        if !self.is_multipath {
            self.get_active_mut()?.need_send_ping = true;
            return Ok(());
        }

        // If multipath is enabled, schedule a Ping frame on the specified path
        // or all the active paths.
        if let Some(a) = path_addr {
            let pid = match self.get_path_id(&(a.local, a.remote)) {
                Some(pid) => pid,
                None => return Ok(()),
            };
            self.get_mut(pid)?.need_send_ping = true;
            return Ok(());
        }
        for (_, path) in self.paths.iter_mut() {
            if path.active() {
                path.need_send_ping = true;
            }
        }
        Ok(())
    }

    /// Promote to multipath mode.
    pub fn enable_multipath(&mut self) {
        self.is_multipath = true;
    }
}
