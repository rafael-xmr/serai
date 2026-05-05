//! Random event, state, and block generator for fuzz testing.

use std::collections::{HashMap, HashSet};

use rand_core::{RngCore as _, OsRng};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    crypto::KeyPair,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, KeyShares, Session, Slash, ValidatorSet},
    test_helpers::{
      random_external_address, random_external_key, random_keypair, random_serai_address,
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
}

impl EventFuzzer {
  #[expect(clippy::new_without_default)]
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

  /// Generate a random SetDecided event.
  fn random_set_decided(&mut self) -> Option<Event> {
    let external_networks: Vec<ExternalNetworkId> =
      self.networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();
    let network = *Self::pick(&external_networks);
    let session_num = *self.next_session.entry(network).or_insert(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Don't double-decide a set that's already pending keys
    if self.pending_keys.contains_key(&set) {
      return None;
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

    let validators_with_shares: Vec<(SeraiAddress, KeyShares)> =
      chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect();

    Some(set_decided_event(
      ValidatorSet { network: NetworkId::External(network), session: Session(session_num) },
      validators_with_shares,
    ))
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

    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
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

    for _ in 0 .. num_events {
      match OsRng.next_u64() % 7 {
        0 => alloc_count += 1,
        1 => dealloc_count += 1,
        2 => set_decided_count += 1,
        3 => set_keys_count += 1,
        4 => burn_count += 1,
        5 => batch_count += 1,
        6 => slash_report_count += 1,
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
      if let Some(e) = self.random_set_decided() {
        events.push(e);
      }
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
