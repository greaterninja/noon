// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! On-demand chain requests over LES. This is a major building block for RPCs.
//! The request service is implemented using Futures. Higher level request handlers
//! will take the raw data received here and extract meaningful results from it.

use std::cmp;
use std::collections::{HashMap, HashSet, BTreeSet};
use std::marker::PhantomData;
use std::sync::Arc;

use ethcore::executed::{Executed, ExecutionError};

use futures::{Poll, Future, Async};
use futures::sync::oneshot::{self, Receiver};
use network::PeerId;
use parking_lot::{RwLock, Mutex};
use rand;
use std::time::{Duration, SystemTime};

use net::{
	self, Handler, PeerStatus, Status, Capabilities,
	Announcement, EventContext, BasicContext, ReqId,
};
use cache::Cache;
use request::{self as basic_request, Request as NetworkRequest};
use self::request::CheckedRequest;

pub use self::request::{Request, Response, HeaderRef};

#[cfg(test)]
mod tests;

pub mod request;

/// The result of execution
pub type ExecutionResult = Result<Executed, ExecutionError>;

/// The default number of retries for OnDemand queries to send to the other nodes
pub const DEFAULT_RETRY_COUNT: usize = 10;

/// The default time limit in milliseconds for inactive (no new peer to connect to) OnDemand queries (0 for unlimited)
pub const DEFAULT_QUERY_TIME_LIMIT: Duration = Duration::from_millis(10000);

const NULL_DURATION: Duration = Duration::from_secs(0);

/// OnDemand related errors
pub mod error {
	use futures::sync::oneshot::Canceled;

	error_chain! {

		foreign_links {
			ChannelCanceled(Canceled) #[doc = "Canceled oneshot channel"];
		}

		errors {
			#[doc = "Request was faulty"]
			FaultyRequest(req_id: super::ReqId, bad_responses: usize, num_providers: usize) {
				description("Faulty request found")
				display("The request: {} was determined as faulty, {}/{} peer(s) gave bad response", req_id, bad_responses, num_providers)
			}

			#[doc = "Max number of on-demand query attempts reached without result."]
			MaxAttemptReach(query_index: usize) {
				description("On-demand query limit reached")
				display("On-demand query limit reached on query #{}", query_index)
			}

			#[doc = "No reply with current peer set, time out occured while waiting for new peers for additional query attempt."]
			TimeoutOnNewPeers(query_index: usize, remaining_attempts: usize) {
				description("Timeout for On-demand query")
				display("Timeout for On-demand query; {} query attempts remain for query #{}", remaining_attempts, query_index)
			}

		}

	}

}

// relevant peer info.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Peer {
	status: Status,
	capabilities: Capabilities,
}

impl Peer {
	// whether this peer can fulfill the necessary capabilities for the given
	// request.
	fn can_fulfill(&self, request: &Capabilities) -> bool {
		let local_caps = &self.capabilities;
		let can_serve_since = |req, local| {
			match (req, local) {
				(Some(request_block), Some(serve_since)) => request_block >= serve_since,
				(Some(_), None) => false,
				(None, _) => true,
			}
		};

		local_caps.serve_headers >= request.serve_headers &&
			can_serve_since(request.serve_chain_since, local_caps.serve_chain_since) &&
			can_serve_since(request.serve_state_since, local_caps.serve_state_since)
	}
}


/// Either an array of responses or a single error.
type PendingResponse = self::error::Result<Vec<Response>>;

// Attempted request info and sender to put received value.
struct Pending {
	requests: basic_request::Batch<CheckedRequest>,
	net_requests: basic_request::Batch<NetworkRequest>,
	required_capabilities: Capabilities,
	responses: Vec<Response>,
	sender: oneshot::Sender<PendingResponse>,
	// This will collect how many bad responses we get from each peer per request
	// When we get `|bad_responses| > peers / 2` then regard the reques as `faulty`
	// This, can happen for several reasons such as a request for a hash that doesn't exist
	bad_responses: HashSet<PeerId>,
	base_query_index: usize,
	remaining_query_count: usize,
	query_id_history: BTreeSet<PeerId>,
	inactive_time_limit: Option<SystemTime>,
}

impl Pending {
	// answer as many of the given requests from the supplied cache as possible.
	// TODO: support re-shuffling.
	fn answer_from_cache(&mut self, cache: &Mutex<Cache>) {
		while !self.requests.is_complete() {
			let idx = self.requests.num_answered();
			match self.requests[idx].respond_local(cache) {
				Some(response) => {
					self.requests.supply_response_unchecked(&response);

					// update header and back-references after each from-cache
					// response to ensure that the requests are left in a consistent
					// state and increase the likelihood of being able to answer
					// the next request from cache.
					self.update_header_refs(idx, &response);
					self.fill_unanswered();

					self.responses.push(response);
				}
				None => break,
			}
		}
	}

	// update header refs if the given response contains a header future requests require for
	// verification.
	// `idx` is the index of the request the response corresponds to.
	fn update_header_refs(&mut self, idx: usize, response: &Response) {
		if let Response::HeaderByHash(ref hdr) = *response {
				// fill the header for all requests waiting on this one.
				// TODO: could be faster if we stored a map usize => Vec<usize>
				// but typical use just has one header request that others
				// depend on.
			for r in self.requests.iter_mut().skip(idx + 1) {
				if r.needs_header().map_or(false, |(i, _)| i == idx) {
					r.provide_header(hdr.clone())
				}
			}
		}
	}

	// supply a response.
	fn supply_response(&mut self, cache: &Mutex<Cache>, response: &basic_request::Response)
		-> Result<(), basic_request::ResponseError<self::request::Error>>
	{
		match self.requests.supply_response(&cache, response) {
			Ok(response) => {
				let idx = self.responses.len();
				self.update_header_refs(idx, &response);
				self.responses.push(response);
				Ok(())
			}
			Err(e) => Err(e),
		}
	}

	// if the requests are complete, send the result and consume self.
	fn try_complete(self) -> Option<Self> {
		if self.requests.is_complete() {
			if self.sender.send(Ok(self.responses)).is_err() {
				debug!(target: "on_demand", "Dropped oneshot channel receiver on complete request at query #{}", self.query_id_history.len());
			}
			None
		} else {
			Some(self)
		}
	}

	fn fill_unanswered(&mut self) {
		self.requests.fill_unanswered();
	}

	// update the cached network requests.
	fn update_net_requests(&mut self) {
		use request::IncompleteRequest;

		let mut builder = basic_request::Builder::default();
		let num_answered = self.requests.num_answered();
		let mut mapping = move |idx| idx - num_answered;

		for request in self.requests.iter().skip(num_answered) {
			let mut net_req = request.clone().into_net_request();

			// all back-references with request index less than `num_answered` have
			// been filled by now. all remaining requests point to nothing earlier
			// than the next unanswered request.
			net_req.adjust_refs(&mut mapping);
			builder.push(net_req)
				.expect("all back-references to answered requests have been filled; qed");
		}

		// update pending fields.
		let capabilities = guess_capabilities(&self.requests[num_answered..]);
		self.net_requests = builder.build();
		self.required_capabilities = capabilities;
	}

	fn add_bad_response(&mut self, peer: PeerId) {
		self.bad_responses.insert(peer);
	}

	fn is_bad_response(&self, total_peers: usize) -> bool {
		self.bad_responses.len() > total_peers / 2
	}

	// returning no reponse, it will result in an error.
	// self is consumed on purpose.
	fn no_response(self) {
		trace!(target: "on_demand", "Dropping a pending query (no reply) at query #{}", self.query_id_history.len());
		let err = self::error::ErrorKind::MaxAttemptReach(self.requests.num_answered());
		if self.sender.send(Err(err.into())).is_err() {
			debug!(target: "on_demand", "Dropped oneshot channel receiver on no response");
		}
	}

	// returning a peer discovery timeout during query attempts
	fn time_out(self) {
		trace!(target: "on_demand", "Dropping a pending query (no new peer time out) at query #{}", self.query_id_history.len());
		let err = self::error::ErrorKind::TimeoutOnNewPeers(self.requests.num_answered(), self.query_id_history.len());
		if self.sender.send(Err(err.into())).is_err() {
			debug!(target: "on_demand", "Dropped oneshot channel receiver on time out");
		}
	}
	
	// returning a faulty request error
	fn set_as_faulty_request(self, total_peers: usize, req_id: ReqId) {
		let bad_peers = self.bad_responses.len();
		warn!(target: "on_demand", "The request: {} was determined as faulty, {}/{} peer(s) gave bad response", req_id, bad_peers, total_peers);
		let err = self::error::ErrorKind::FaultyRequest(req_id, bad_peers, total_peers);
		if self.sender.send(Err(err.into())).is_err() {
			debug!(target: "on_demand", "Dropped oneshot channel receiver on time out");
		}
	}
}

// helper to guess capabilities required for a given batch of network requests.
fn guess_capabilities(requests: &[CheckedRequest]) -> Capabilities {
	let mut caps = Capabilities {
		serve_headers: false,
		serve_chain_since: None,
		serve_state_since: None,
		tx_relay: false,
	};

	let update_since = |current: &mut Option<u64>, new|
		*current = match *current {
			Some(x) => Some(::std::cmp::min(x, new)),
			None => Some(new),
		};

	for request in requests {
		match *request {
			// TODO: might be worth returning a required block number for this also.
			CheckedRequest::HeaderProof(_, _) =>
				caps.serve_headers = true,
			CheckedRequest::HeaderByHash(_, _) =>
				caps.serve_headers = true,
			CheckedRequest::HeaderWithAncestors(_, _) =>
				caps.serve_headers = true,
			CheckedRequest::TransactionIndex(_, _) => {} // hashes yield no info.
			CheckedRequest::Signal(_, _) =>
				caps.serve_headers = true,
			CheckedRequest::Body(ref req, _) => if let Ok(ref hdr) = req.0.as_ref() {
				update_since(&mut caps.serve_chain_since, hdr.number());
			},
			CheckedRequest::Receipts(ref req, _) => if let Ok(ref hdr) = req.0.as_ref() {
				update_since(&mut caps.serve_chain_since, hdr.number());
			},
			CheckedRequest::Account(ref req, _) => if let Ok(ref hdr) = req.header.as_ref() {
				update_since(&mut caps.serve_state_since, hdr.number());
			},
			CheckedRequest::Code(ref req, _) => if let Ok(ref hdr) = req.header.as_ref() {
				update_since(&mut caps.serve_state_since, hdr.number());
			},
			CheckedRequest::Execution(ref req, _) => if let Ok(ref hdr) = req.header.as_ref() {
				update_since(&mut caps.serve_state_since, hdr.number());
			},
		}
	}

	caps
}

/// A future extracting the concrete output type of the generic adapter
/// from a vector of responses.
pub struct OnResponses<T: request::RequestAdapter> {
	receiver: Receiver<PendingResponse>,
	_marker: PhantomData<T>,
}

impl<T: request::RequestAdapter> Future for OnResponses<T> {
	type Item = T::Out;
	type Error = self::error::Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		match self.receiver.poll() {
			Ok(Async::Ready(Ok(v))) => Ok(Async::Ready(T::extract_from(v))),
			Ok(Async::Ready(Err(e))) => Err(e),
			Ok(Async::NotReady) => Ok(Async::NotReady),
			Err(e) => Err(e.into()),
		}
	}
}

/// On demand request service. See module docs for more details.
/// Accumulates info about all peers' capabilities and dispatches
/// requests to them accordingly.
// lock in declaration order.
pub struct OnDemand {
	pending: RwLock<Vec<Pending>>,
	peers: RwLock<HashMap<PeerId, Peer>>,
	in_transit: RwLock<HashMap<ReqId, Pending>>,
	cache: Arc<Mutex<Cache>>,
	no_immediate_dispatch: bool,
	base_retry_count: usize,
	query_inactive_time_limit: Option<Duration>,
}

impl OnDemand {

	/// Create a new `OnDemand` service with the given cache.
	pub fn new(cache: Arc<Mutex<Cache>>) -> Self {
		OnDemand {
			pending: RwLock::new(Vec::new()),
			peers: RwLock::new(HashMap::new()),
			in_transit: RwLock::new(HashMap::new()),
			cache,
			no_immediate_dispatch: false,
			base_retry_count: DEFAULT_RETRY_COUNT,
			query_inactive_time_limit: Some(DEFAULT_QUERY_TIME_LIMIT),
		}
	}

	// make a test version: this doesn't dispatch pending requests
	// until you trigger it manually.
	#[cfg(test)]
	fn new_test(cache: Arc<Mutex<Cache>>) -> Self {
		let mut me = OnDemand::new(cache);
		me.no_immediate_dispatch = true;

		me
	}

	/// Submit a vector of requests to be processed together.
	///
	/// Fails if back-references are not coherent.
	/// The returned vector of responses will correspond to the requests exactly.
	pub fn request_raw(&self, ctx: &BasicContext, requests: Vec<Request>)
		-> Result<Receiver<PendingResponse>, basic_request::NoSuchOutput>
	{
		let (sender, receiver) = oneshot::channel();
		if requests.is_empty() {
			assert!(sender.send(Ok(Vec::new())).is_ok(), "receiver still in scope; qed");
			return Ok(receiver);
		}

		let mut builder = basic_request::Builder::default();

		let responses = Vec::with_capacity(requests.len());

		let mut header_producers = HashMap::new();
		for (i, request) in requests.into_iter().enumerate() {
			let request = CheckedRequest::from(request);

			// ensure that all requests needing headers will get them.
			if let Some((idx, field)) = request.needs_header() {
				// a request chain with a header back-reference is valid only if it both
				// points to a request that returns a header and has the same back-reference
				// for the block hash.
				match header_producers.get(&idx) {
					Some(ref f) if &field == *f => {}
					_ => return Err(basic_request::NoSuchOutput),
				}
			}
			if let CheckedRequest::HeaderByHash(ref req, _) = request {
				header_producers.insert(i, req.0);
			}

			builder.push(request)?;
		}

		let requests = builder.build();
		let net_requests = requests.clone().map_requests(|req| req.into_net_request());
		let capabilities = guess_capabilities(requests.requests());

		self.submit_pending(ctx, Pending {
			requests,
			net_requests,
			required_capabilities: capabilities,
			responses,
			sender,
			bad_responses: HashSet::new(),
			base_query_index: 0,
			remaining_query_count: 0,
			query_id_history: BTreeSet::new(),
			inactive_time_limit: None,
		});

		Ok(receiver)
	}

	/// Submit a strongly-typed batch of requests.
	///
	/// Fails if back-reference are not coherent.
	pub fn request<T>(&self, ctx: &BasicContext, requests: T) -> Result<OnResponses<T>, basic_request::NoSuchOutput>
		where T: request::RequestAdapter
	{
		self.request_raw(ctx, requests.make_requests()).map(|recv| OnResponses {
			receiver: recv,
			_marker: PhantomData,
		})
	}

	// maybe dispatch pending requests.
	// sometimes
	fn attempt_dispatch(&self, ctx: &BasicContext) {
		if !self.no_immediate_dispatch {
			self.dispatch_pending(ctx)
		}
	}

	// dispatch pending requests, and discard those for which the corresponding
	// receiver has been dropped.
	fn dispatch_pending(&self, ctx: &BasicContext) {
		if self.pending.read().is_empty() { return }
		let mut pending = self.pending.write();

		debug!(target: "on_demand", "Attempting to dispatch {} pending requests", pending.len());

		// iterate over all pending requests, and check them for hang-up.
		// then, try and find a peer who can serve it.
		let peers = self.peers.read();
		*pending = ::std::mem::replace(&mut *pending, Vec::new()).into_iter()
			.filter(|pending| !pending.sender.is_canceled())
			.filter_map(|mut pending| {
				// the peer we dispatch to is chosen randomly
				let num_peers = peers.len();
				let history_len = pending.query_id_history.len();
				let offset = if history_len == 0 {
					pending.remaining_query_count = self.base_retry_count;
					let rand = rand::random::<usize>();
					pending.base_query_index = rand;
					rand
				} else {
					pending.base_query_index + history_len
				} % cmp::max(num_peers, 1);
				let init_remaining_query_count = pending.remaining_query_count; // to fail in case of big reduction of nb of peers
				for (peer_id, peer) in peers.iter().chain(peers.iter())
					.skip(offset).take(num_peers) {
					// TODO: see which requests can be answered by the cache?
					if pending.remaining_query_count == 0 {
						break
					}

					if pending.query_id_history.insert(peer_id.clone()) {

						if !peer.can_fulfill(&pending.required_capabilities) {
							trace!(target: "on_demand", "Peer {} without required capabilities, skipping, {} remaining attempts", peer_id, pending.remaining_query_count);
							continue
						}

						pending.remaining_query_count -= 1;
						pending.inactive_time_limit = None;

						match ctx.request_from(*peer_id, pending.net_requests.clone()) {
							Ok(req_id) => {
								trace!(target: "on_demand", "Dispatched request {} to peer {}, {} remaining attempts", req_id, peer_id, pending.remaining_query_count);
								self.in_transit.write().insert(req_id, pending);
								return None
							}
							Err(net::Error::NoCredits) | Err(net::Error::NotServer) => {}
							Err(e) => debug!(target: "on_demand", "Error dispatching request to peer: {}", e),
						}
					}
				}

				if pending.remaining_query_count == 0	{
					pending.no_response();
					None
				} else if init_remaining_query_count == pending.remaining_query_count {
					if let Some(query_inactive_time_limit) = self.query_inactive_time_limit {
						let now = SystemTime::now();
						if let Some(inactive_time_limit) = pending.inactive_time_limit {
							if now > inactive_time_limit {
								pending.time_out();
								return None
							}
						} else {
							debug!(target: "on_demand", "No more peers to query, waiting for {} seconds until dropping query", query_inactive_time_limit.as_secs());
							pending.inactive_time_limit = Some(now + query_inactive_time_limit);
						}
					}
					Some(pending)
				} else {
					Some(pending)
				}
			})
			.collect(); // `pending` now contains all requests we couldn't dispatch.

		debug!(target: "on_demand", "Was unable to dispatch {} requests.", pending.len());
	}

	// submit a pending request set. attempts to answer from cache before
	// going to the network. if complete, sends response and consumes the struct.
	fn submit_pending(&self, ctx: &BasicContext, mut pending: Pending) {
		// answer as many requests from cache as we can, and schedule for dispatch
		// if incomplete.

		pending.answer_from_cache(&*self.cache);
		if let Some(mut pending) = pending.try_complete() {
			pending.update_net_requests();
			self.pending.write().push(pending);
			self.attempt_dispatch(ctx);
		}
	}

	/// Set the retry count for a query.
	pub fn default_retry_number(&mut self, nb_retry: usize) {
		self.base_retry_count = nb_retry;
	}

	/// Set the time limit for a query.
	pub fn query_inactive_time_limit(&mut self, inactive_time_limit: Duration) {
		self.query_inactive_time_limit = if inactive_time_limit == NULL_DURATION {
			None
		} else {
			Some(inactive_time_limit)
		};
	}

}

impl Handler for OnDemand {
	fn on_connect(
		&self,
		ctx: &EventContext,
		status: &Status,
		capabilities: &Capabilities
	) -> PeerStatus {
		self.peers.write().insert(
			ctx.peer(),
			Peer { status: status.clone(), capabilities: *capabilities }
		);
		self.attempt_dispatch(ctx.as_basic());
		PeerStatus::Kept
	}

	fn on_disconnect(&self, ctx: &EventContext, unfulfilled: &[ReqId]) {
		self.peers.write().remove(&ctx.peer());
		let ctx = ctx.as_basic();

		{
			let mut pending = self.pending.write();
			for unfulfilled in unfulfilled {
				if let Some(unfulfilled) = self.in_transit.write().remove(unfulfilled) {
					trace!(target: "on_demand", "Attempting to reassign dropped request");
					pending.push(unfulfilled);
				}
			}
		}

		self.attempt_dispatch(ctx);
	}

	fn on_announcement(&self, ctx: &EventContext, announcement: &Announcement) {
		{
			let mut peers = self.peers.write();
			if let Some(ref mut peer) = peers.get_mut(&ctx.peer()) {
				peer.status.update_from(&announcement);
				peer.capabilities.update_from(&announcement);
			}
		}

		self.attempt_dispatch(ctx.as_basic());
	}

	fn on_responses(&self, ctx: &EventContext, req_id: ReqId, responses: &[basic_request::Response]) {
		let mut pending = match self.in_transit.write().remove(&req_id) {
			Some(req) => req,
			None => return,
		};

		if responses.is_empty() {
			if pending.remaining_query_count == 0 {
				pending.no_response();
				return;
			}
		} else {
			// do not keep query counter for others elements of this batch
			pending.query_id_history.clear();
		}

		// for each incoming response
		//   1. ensure verification data filled.
		//   2. pending.requests.supply_response
		//   3. if extracted on-demand response, keep it for later.
		for response in responses {
			trace!(target: "on_demand", "got a response: {} {:?}", req_id, response);

			// this does not punish a peer with bad response anymore because
			// we can't actually tell whether the request or the provider was faulty
			// so let's rely on the majority of the network instead
			if let Err(e) = pending.supply_response(&*self.cache, response) {
				let peer = ctx.peer();
				trace!(target: "on_demand", "Peer {} gave bad response on req_id: {} because of: {:?}", peer, req_id, e);
				pending.add_bad_response(peer);
				let total_peers = self.peers.read().len();
				if pending.is_bad_response(total_peers) {
					pending.set_as_faulty_request(total_peers, req_id);
					return;
				}
			}
		}

		pending.fill_unanswered();
		self.submit_pending(ctx.as_basic(), pending);
	}

	fn tick(&self, ctx: &BasicContext) {
		self.attempt_dispatch(ctx)
	}
}
