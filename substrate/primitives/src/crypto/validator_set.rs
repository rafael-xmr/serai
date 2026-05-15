use alloc::vec::Vec;
use dalek_ff_group::Ristretto;
use std_shims::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};
use ciphersuite::{group::GroupEncoding, WrappedGroup};
use dkg::Participant;

/// A validator's substrate and network auxiliary keys with a weight.
#[derive(Clone, Hash, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct TributaryValidator {
  /// The validator's Substrate auxiliary key.
  pub substrate_key: [u8; 32],
  /// The validator's network-specific auxiliary key.
  pub network_key: Vec<u8>,
  /// The validator's weight within the set.
  pub weight: u16,
}

impl TributaryValidator {
  /// Create a new `ValidatorWithWeight`.
  pub fn new(substrate_key: [u8; 32], network_key: Vec<u8>, weight: u16) -> Self {
    Self { substrate_key, network_key, weight }
  }
}

/// A list of validators with their substrate/network keys and weights.
///
/// This is a wrapper around `Vec<(([u8; 32], Vec<u8>), u16)>` which
/// provides helper methods for common operations.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(init = init_participant_indexes)]
pub struct TributaryValidatorSet {
  /// A list of validators with their substrate/network keys and weights.
  pub validators: Vec<TributaryValidator>,
  /// The participant indexes, indexed by their validator.
  #[borsh(skip)]
  pub participant_indexes: HashMap<TributaryValidator, Vec<Participant>>,
  /// The validators, indexed by their participant indexes.
  #[borsh(skip)]
  pub participant_indexes_reverse_lookup: HashMap<Participant, TributaryValidator>,
}

impl TributaryValidatorSet {
  /// Create a new empty validator set.
  pub fn new() -> Self {
    Self {
      validators: Vec::new(),
      participant_indexes: HashMap::new(),
      participant_indexes_reverse_lookup: HashMap::new(),
    }
  }

  /// Get the underlying list of validators.
  pub fn as_slice(&self) -> &[TributaryValidator] {
    &self.validators
  }

  /// Get a validator by their auxiliary key address (derived from Substrate key).
  pub fn get_by_substrate_public(
    &self,
    substrate_public: &<Ristretto as WrappedGroup>::G,
  ) -> Option<&TributaryValidator> {
    self.validators.iter().find(|v| v.substrate_key == substrate_public.to_bytes())
  }

  /// Get a validator by their Substrate auxiliary key address.
  pub fn get_by_participant(&self, participant: &Participant) -> Option<&TributaryValidator> {
    self.participant_indexes_reverse_lookup.iter().find(|(p, _)| *p == participant).map(|(_, v)| v)
  }

  /// Get a validator by their Substrate auxiliary key address.
  pub fn get_participant_matches_substrate_public(
    &self,
    participant: &Participant,
    substrate_public: &<Ristretto as WrappedGroup>::G,
  ) -> bool {
    self
      .participant_indexes_reverse_lookup
      .iter()
      .find(|(p, v)| *p == participant && v.substrate_key == substrate_public.to_bytes())
      .is_some()
  }

  /// Get a validator by their Substrate auxiliary key address.
  pub fn get_participant_by_validator(
    &self,
    validator: &TributaryValidator,
  ) -> Option<&Participant> {
    self.participant_indexes_reverse_lookup.iter().find(|(_, v)| *v == validator).map(|(p, _)| p)
  }

  /// Get a validator by their Substrate auxiliary key address.
  pub fn get_participant_by_substrate_public(
    &self,
    substrate_public: &<Ristretto as WrappedGroup>::G,
  ) -> Option<&Participant> {
    self
      .participant_indexes_reverse_lookup
      .iter()
      .find(|(_, v)| v.substrate_key == substrate_public.to_bytes())
      .map(|(p, _)| p)
  }

  /// Get the total weight of all validators in the set.
  pub fn total_weight(&self) -> u16 {
    let total_weight = self.validators.iter().map(|v| u32::from(v.weight)).sum::<u32>();
    let total_weight = u16::try_from(total_weight)
      .expect("value smaller than `u16` constant but doesn't fit in `u16`");
    total_weight
  }

  /// Accordingly sync up participant indexes and reverse lookup with `validators`.
  pub fn init_participant_indexes(&mut self) {
    let mut next_participant_index = 1;
    self.participant_indexes = HashMap::with_capacity(self.validators.len());
    self.participant_indexes_reverse_lookup = HashMap::with_capacity(self.validators.len());

    for validator in &self.validators {
      let weight = validator.weight;
      let mut this_validator_participants = Vec::with_capacity((weight).into());
      for _ in 0 .. weight {
        let this_participant = Participant::new(next_participant_index).unwrap();
        next_participant_index += 1;

        this_validator_participants.push(this_participant);
        self.participant_indexes_reverse_lookup.insert(this_participant, validator.clone());
      }
      self.participant_indexes.insert(validator.clone(), this_validator_participants);
    }
  }

  /// Get len of the validator items
  pub fn len(&self) -> usize {
    self.validators.len()
  }

  /// Get the threshold for the EVRF protocol, calculated as `(2/3 * len) + 1`.
  pub fn threshold(&self) -> u16 {
    let len = self.participant_indexes.len();
    u16::try_from(((len * 2) / 3) + 1).unwrap()
  }

  /// Get the substrate public keys from the EVRF public keys.
  pub fn substrate_evrf_public_keys(&self) -> Vec<[u8; 32]> {
    self.participant_indexes.iter().map(|(key, _)| key.substrate_key).collect()
  }

  /// Get the network public keys from the EVRF public keys.
  pub fn network_evrf_public_keys(&self) -> Vec<Vec<u8>> {
    self.participant_indexes.keys().map(|key| key.network_key.clone()).collect()
  }
}

impl Default for TributaryValidatorSet {
  fn default() -> Self {
    Self::new()
  }
}
