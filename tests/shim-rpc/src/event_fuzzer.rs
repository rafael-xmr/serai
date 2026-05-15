//! Random event, state, and block generator for fuzz testing.

use std::collections::{HashMap, HashSet};

use rand_core::{RngCore as _, OsRng};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    crypto::{EmbeddedEllipticCurveKeys, KeyPair},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, KeyShares, Session, Slash, ValidatorSet},
    test_helpers::{
      random_embedded_elliptic_curve_keys, random_external_address, random_external_key,
      random_keypair, random_serai_address, random_serai_embedded_elliptic_curve_keys,
    },
  },
  validator_sets, Event,
};

use crate::{test_helpers::*, event_generator::in_instructions_events};

/// Random event, state, and block generator.
pub struct EventFuzzer {
  /// Available validator addresses.
  pub validators: Vec<SeraiAddress>,
  /// All networks.
  networks: Vec<NetworkId>,
  /// External networks.
  external_networks: Vec<ExternalNetworkId>,
  /// Running stake ledger: `(network, validator) -> accumulated_stake`.
  // TODO: Track for `NetworkId`, not `ExternalNetworkId`
  stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64>,
  /// Sets that have been decided but have not yet set their keys.
  pending_keys: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  /// Next session number per network.
  pub next_session: HashMap<ExternalNetworkId, u32>,
  /// Keypairs indexed by public key bytes, for signing cosigns.
  pub keypairs: HashMap<[u8; 32], schnorrkel::Keypair>,
  /// Networks that have already received a Batch event this block.
  batches_this_block: HashSet<ExternalNetworkId>,
  /// Next batch ID per network (increments by 1 per batch).
  batch_ids: HashMap<ExternalNetworkId, u32>,
  /// Cached auxiliary keys per (network, validator) — stable across sessions so that every
  /// SetEmbeddedEllipticCurveKeys event for the same pair always carries the same key value,
  /// keeping the DB consistent with historical events.
  aux_key_cache: HashMap<(ExternalNetworkId, SeraiAddress), EmbeddedEllipticCurveKeys>,
  /// Cached Serai-network auxiliary keys per validator, for the same stability reason.
  serai_key_cache: HashMap<SeraiAddress, EmbeddedEllipticCurveKeys>,
  /// Sets that have completed keygen (SetKeys was received), eligible for AcceptedHandover.
  completed_sets: Vec<ExternalValidatorSet>,
  /// Next session number for the Serai network itself.
  next_serai_session: u32,
  /// Serai sessions that have been decided, eligible for a Serai AcceptedHandover.
  completed_serai_sessions: Vec<u32>,
}

impl Default for EventFuzzer {
  fn default() -> Self {
    Self::new()
  }
}

impl EventFuzzer {
  pub fn new() -> Self {
    // OsRng.next_u64() % 17 = 0..16, + 4 means from 4..20 validators per test
    let num_validators = usize::try_from((OsRng.next_u64() % 17) + 4).unwrap();

    let validators: Vec<SeraiAddress> =
      (0 .. num_validators).map(|_| random_serai_address(&mut OsRng)).collect();

    let networks: Vec<NetworkId> = NetworkId::all().collect();
    let external_networks: Vec<ExternalNetworkId> =
      networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();

    Self {
      validators,
      networks,
      external_networks,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
      batches_this_block: HashSet::new(),
      batch_ids: HashMap::new(),
      aux_key_cache: HashMap::new(),
      serai_key_cache: HashMap::new(),
      completed_sets: Vec::new(),
      next_serai_session: 0,
      completed_serai_sessions: Vec::new(),
    }
  }

  /// Create a new fuzzer seeding extra validators into the pool.
  pub fn new_with_validators(extra_validators: &[SeraiAddress]) -> Self {
    // OsRng.next_u64() % 17 = 0..16, + 4 means from 4..20 validators per test
    let num_validators = usize::try_from((OsRng.next_u64() % 17) + 4).unwrap();

    let mut validators: Vec<SeraiAddress> =
      (0 .. num_validators).map(|_| random_serai_address(&mut OsRng)).collect();
    validators.extend_from_slice(extra_validators);

    let networks: Vec<NetworkId> = NetworkId::all().collect();
    let external_networks: Vec<ExternalNetworkId> =
      networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();

    Self {
      validators,
      networks,
      external_networks,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
      batches_this_block: HashSet::new(),
      batch_ids: HashMap::new(),
      aux_key_cache: HashMap::new(),
      serai_key_cache: HashMap::new(),
      completed_sets: Vec::new(),
      next_serai_session: 0,
      completed_serai_sessions: Vec::new(),
    }
  }

  /// Pick a random element from a slice.
  fn pick<T>(slice: &[T]) -> &T {
    let i = OsRng.next_u64() % u64::try_from(slice.len()).unwrap();
    &slice[usize::try_from(i).unwrap()]
  }

  /// Generate a random amount using a weighted distribution.
  fn random_amount() -> u64 {
    match OsRng.next_u64() % 100 {
      0 ..= 24 => (OsRng.next_u64() % 10) + 1,
      25 ..= 59 => (OsRng.next_u64() % 990) + 11,
      60 ..= 84 => (OsRng.next_u64() % 99_000) + 1_001,
      _ => (OsRng.next_u64() % 9_900_000) + 100_001,
    }
  }

  /// Generate a random allocation event.
  fn random_allocation(&mut self) -> Event {
    let validator = *Self::pick(&self.validators.clone());
    let network = *Self::pick(&self.networks.clone());
    let amount = Self::random_amount();
    if let Ok(ext) = ExternalNetworkId::try_from(network) {
      *self.stakes.entry((ext, validator)).or_default() += amount;
    }
    allocation_event(validator, network, amount)
  }

  /// Generate a random deallocation event. Returns `None` if no validator has stake.
  fn random_deallocation(&mut self) -> Option<Event> {
    // ~25% chance of generating a Serai deallocation
    if OsRng.next_u64() % 4 == 0 {
      let validator = *Self::pick(&self.validators.clone());
      let amount = Self::random_amount();
      return Some(deallocation_event(validator, NetworkId::Serai, amount));
    }

    let candidates: Vec<((ExternalNetworkId, SeraiAddress), u64)> = self
      .stakes
      .iter()
      .filter(|(_v, &stake)| stake > 0)
      .map(|(&validator, &stake)| (validator, stake))
      .collect();
    if candidates.is_empty() {
      return None;
    }
    let &((network, validator), current_stake) = Self::pick(&candidates);
    // Use weighted amount, clamped to current_stake so we don't underflow
    let amount = Self::random_amount().min(current_stake);
    *self.stakes.entry((network, validator)).or_default() -= amount;
    Some(deallocation_event(validator, NetworkId::External(network), amount))
  }

  /// Generate a SetDecided event, with a 1-in-4 chance it is for `NetworkId::Serai`.
  ///
  /// For external networks the event is preceded by `SetEmbeddedEllipticCurveKeys` for each
  /// validator (required by the chain invariant). For `NetworkId::Serai` no key events are
  /// emitted — the implementation filters Serai SetDecided out, exercising the skip path.
  ///
  /// Returns an empty vec if an external set for the chosen network is already pending keys.
  fn random_set_decided(&mut self) -> Vec<Event> {
    // 1-in-4 chance: emit a Serai-network SetDecided (filtered by the implementation).
    if OsRng.next_u64() % 4 == 0 {
      let session_num = self.next_serai_session;
      self.next_serai_session += 1;
      self.completed_serai_sessions.push(session_num);

      let max_count = self.validators.len().min(3);
      let count =
        usize::try_from((OsRng.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();
      let mut pool = self.validators.clone();
      let mut chosen = Vec::with_capacity(count);
      for _ in 0 .. count {
        let i = usize::try_from(OsRng.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
        chosen.push(pool.swap_remove(i));
      }
      let validators_with_shares =
        chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect::<Vec<_>>();
      return vec![set_decided_event(
        ValidatorSet { network: NetworkId::Serai, session: Session(session_num) },
        validators_with_shares,
      )];
    }

    let external_networks: Vec<ExternalNetworkId> =
      self.networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();
    let network = *Self::pick(&external_networks);
    let session_num = *self.next_session.entry(network).or_insert(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Don't double-decide a set that's already pending keys
    if self.pending_keys.contains_key(&set) {
      return vec![];
    }

    // Pick 1..=min(3, validators.len()) random validators for this set
    let max_count = self.validators.len().min(3);
    let count =
      usize::try_from((OsRng.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();

    // Shuffle-pick by swapping from a clone
    let mut pool = self.validators.clone();
    let mut chosen = Vec::with_capacity(count);
    for _ in 0 .. count {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
      chosen.push(pool.swap_remove(i));
    }

    self.pending_keys.insert(set, chosen.clone());

    // Emit SetEmbeddedEllipticCurveKeys for each chosen validator before SetDecided.
    // Keys are cached per (network, validator) so that re-appearances across sessions always
    // emit the same key value — keeping the DB consistent with every historical event.
    let mut events: Vec<Event> = chosen
      .iter()
      .map(|&validator| {
        let keys = *self
          .aux_key_cache
          .entry((network, validator))
          .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut OsRng, network));
        Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys {
          validator,
          keys,
        })
      })
      .collect();

    let validators_with_shares: Vec<(SeraiAddress, KeyShares)> =
      chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect();

    events.push(set_decided_event(
      ValidatorSet { network: NetworkId::External(network), session: Session(session_num) },
      validators_with_shares,
    ));

    events
  }

  /// Generate a random SetKeys event for a pending (decided but not yet keyed) set.
  fn random_set_keys(&mut self) -> Option<Event> {
    if self.pending_keys.is_empty() {
      return None;
    }

    let keys: Vec<ExternalValidatorSet> = self.pending_keys.keys().copied().collect();
    let i = usize::try_from(OsRng.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap();
    let set = keys[i];
    // Remove from pending
    self.pending_keys.remove(&set);

    // Advance session for this network so the next SetDecided gets session+1
    *self.next_session.entry(set.network).or_insert(0) += 1;

    let (keypair, public) = random_keypair(&mut OsRng);
    self.keypairs.insert(public.0, keypair);
    let external_key = random_external_key(&mut OsRng);
    let key_pair = KeyPair(public, external_key);

    self.completed_sets.push(set);
    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
  }

  /// Generate a standalone `SetEmbeddedEllipticCurveKeys` for a random validator on any network,
  /// including `NetworkId::Serai`. Uses the key cache so repeated events for the same
  /// (network, validator) pair always carry the same key value.
  fn random_standalone_embedded_key_event(&mut self) -> Event {
    let validator = *Self::pick(&self.validators.clone());

    // Pick uniformly from all networks (Serai + external).
    let all_networks: Vec<NetworkId> = self.networks.clone();
    let network = *Self::pick(&all_networks);

    let keys = if let Ok(ext) = ExternalNetworkId::try_from(network) {
      *self
        .aux_key_cache
        .entry((ext, validator))
        .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut OsRng, ext))
    } else {
      // Serai network
      *self
        .serai_key_cache
        .entry(validator)
        .or_insert_with(|| random_serai_embedded_elliptic_curve_keys(&mut OsRng))
    };

    Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys { validator, keys })
  }

  /// Generate a random `AcceptedHandover` event for a completed set, including `NetworkId::Serai`.
  /// Returns `None` if no sets have completed yet on any network.
  fn random_accepted_handover(&self) -> Option<Event> {
    let external_count = self.completed_sets.len();
    let serai_count = self.completed_serai_sessions.len();
    let total = external_count + serai_count;
    if total == 0 {
      return None;
    }

    let i = usize::try_from(OsRng.next_u64() % u64::try_from(total).unwrap()).unwrap();
    let set = if i < external_count {
      let ext = self.completed_sets[i];
      ValidatorSet { network: NetworkId::External(ext.network), session: ext.session }
    } else {
      let session_num = self.completed_serai_sessions[i - external_count];
      ValidatorSet { network: NetworkId::Serai, session: Session(session_num) }
    };

    Some(Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set }))
  }

  /// Generate a random BurnWithInstruction event.
  pub fn random_burn(&mut self) -> Event {
    burn_with_instruction_event(
      random_serai_address(&mut OsRng),
      random_external_address(&mut OsRng),
      Self::random_amount(),
    )
  }

  /// Generate a random Batch event.
  pub fn random_batch(&mut self) -> Option<Event> {
    let network = *Self::pick(&self.external_networks.clone());
    if self.batches_this_block.contains(&network) {
      return None;
    }
    self.batches_this_block.insert(network);
    let session_num = *self.next_session.entry(network).or_insert(0);
    self.batch_ids.entry(network).and_modify(|id| *id += 1).or_insert(0);
    let id = *self.batch_ids.entry(network).or_insert(0);
    println!("id: {id} for {network:?}");
    Some(in_instructions_events::batch(&mut OsRng, network, Session(session_num), id))
  }

  /// Generate a random Slashes event for an external network set that has set its keys.
  pub fn random_slash_report(&mut self) -> Option<Event> {
    // Find networks that have at least one session completed (keys have been set)
    let eligible: Vec<ExternalNetworkId> = self
      .external_networks
      .iter()
      .copied()
      .filter(|n| self.next_session.get(n).copied().unwrap_or(0) > 0)
      .collect();
    if eligible.is_empty() {
      return None;
    }

    let network = *Self::pick(&eligible);
    // Session is the most recently keyed session for this network
    let session_num = self.next_session[&network] - 1;
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Build a random SlashReport
    let num_slashes = usize::try_from(OsRng.next_u64() % 4).unwrap() + 1; // 1..=4
    let mut slashes = Vec::with_capacity(num_slashes);
    for _ in 0 .. num_slashes {
      slashes.push(if (OsRng.next_u64() % 4) == 0 {
        Slash::Fatal
      } else {
        Slash::Points(OsRng.next_u32() % 100_000)
      });
    }

    Some(slash_report_event(set))
  }

  /// Generate random events for a single block.
  fn generate_block_events(&mut self) -> Vec<Vec<Event>> {
    // New blocks, reset network batch counter
    self.batches_this_block.clear();

    let num_events = OsRng.next_u64() % 8; // 0..=7 events per block
    if num_events == 0 {
      return vec![];
    }

    let mut alloc_count = 0u64;
    let mut dealloc_count = 0u64;
    let mut set_decided_count = 0u64;
    let mut set_keys_count = 0u64;
    let mut burn_count = 0u64;
    let mut batch_count = 0u64;
    let mut slash_report_count = 0u64;
    let mut embedded_key_count = 0u64;
    let mut accepted_handover_count = 0u64;

    for _ in 0 .. num_events {
      match OsRng.next_u64() % 9 {
        0 => alloc_count += 1,
        1 => dealloc_count += 1,
        2 => set_decided_count += 1,
        3 => set_keys_count += 1,
        4 => burn_count += 1,
        5 => batch_count += 1,
        6 => slash_report_count += 1,
        7 => embedded_key_count += 1,
        8 => accepted_handover_count += 1,
        _ => unreachable!(),
      }
    }

    let mut events = Vec::new();

    for _ in 0 .. alloc_count {
      events.push(self.random_allocation());
    }
    for _ in 0 .. dealloc_count {
      if let Some(e) = self.random_deallocation() {
        events.push(e);
      }
    }
    for _ in 0 .. set_decided_count {
      events.extend(self.random_set_decided());
    }
    for _ in 0 .. set_keys_count {
      if let Some(event) = self.random_set_keys() {
        events.push(event);
      }
    }
    for _ in 0 .. burn_count {
      events.push(self.random_burn());
    }
    for _ in 0 .. batch_count {
      if let Some(event) = self.random_batch() {
        events.push(event);
      }
    }
    for _ in 0 .. slash_report_count {
      if let Some(event) = self.random_slash_report() {
        events.push(event);
      }
    }
    for _ in 0 .. embedded_key_count {
      events.push(self.random_standalone_embedded_key_event());
    }
    for _ in 0 .. accepted_handover_count {
      if let Some(event) = self.random_accepted_handover() {
        events.push(event);
      }
    }

    // Shuffle the events to test order-independence
    for i in (1 .. events.len()).rev() {
      let j = usize::try_from(OsRng.next_u64() % u64::try_from(i + 1).unwrap()).unwrap();
      events.swap(i, j);
    }

    if events.is_empty() {
      vec![]
    } else {
      vec![events]
    }
  }

  /// Force a complete allocation of SetDecided -> SetKeys sequence for every external network,
  /// guaranteeing a global session with multiple validator sets will form.
  fn force_keygen(&mut self) -> [Vec<Vec<Event>>; 3] {
    let external_networks: Vec<ExternalNetworkId> =
      self.networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();

    let mut alloc_events = Vec::new();
    let mut decided_events = Vec::new();
    let mut keys_events = Vec::new();

    for &network in &external_networks {
      let validator = *Self::pick(&self.validators.clone());
      let amount = Self::random_amount();

      *self.stakes.entry((network, validator)).or_default() += amount;
      alloc_events.push(allocation_event(validator, NetworkId::External(network), amount));

      let session_num = *self.next_session.entry(network).or_insert(0);
      let set = ExternalValidatorSet { network, session: Session(session_num) };
      self.pending_keys.insert(set, vec![validator]);

      // Emit SetEmbeddedEllipticCurveKeys before SetDecided to uphold the chain invariant.
      // Use the cache so repeated appearances of the same validator always emit the same key.
      let keys = *self
        .aux_key_cache
        .entry((network, validator))
        .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut OsRng, network));
      decided_events.push(Event::ValidatorSets(
        validator_sets::Event::SetEmbeddedEllipticCurveKeys { validator, keys },
      ));
      decided_events.push(set_decided_event(
        ValidatorSet { network: NetworkId::External(network), session: Session(session_num) },
        vec![(validator, KeyShares::ONE)],
      ));

      self.pending_keys.remove(&set);
      *self.next_session.entry(network).or_insert(0) += 1;
      let (keypair, public) = random_keypair(&mut OsRng);
      self.keypairs.insert(public.0, keypair);
      let external_key = random_external_key(&mut OsRng);
      keys_events.push(Event::ValidatorSets(validator_sets::Event::SetKeys {
        set,
        key_pair: KeyPair(public, external_key),
      }));
    }

    [vec![alloc_events], vec![decided_events], vec![keys_events]]
  }

  /// Generate `count` blocks of random events.
  pub fn generate_blocks(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    let mut blocks = Vec::with_capacity(count);
    for _ in 0 .. count {
      blocks.push(self.generate_block_events());
    }
    blocks
  }

  /// Generate `count` blocks, starting with a forced keygen sequence (3 blocks)
  /// to guarantee at least one global session forms, followed by random blocks.
  pub fn generate_blocks_with_keygen(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    assert!(count >= 4, "need at least 4 blocks for forced keygen + one random block");

    let [alloc, decided, keys] = self.force_keygen();
    let mut blocks = vec![alloc, decided, keys];
    blocks.extend(self.generate_blocks(count - 3));
    blocks
  }
}
