use rand::RngCore as _;
use rand_core::OsRng;
use serai_primitives::{
  crypto::TributaryValidatorSet,
  test_helpers::{default_test_validator_set, random_bytes_32, random_validator_set},
};

use crate::NewSetInformation;

/// A random [`NewSetInformation`] for tests.
pub fn random_test_set_info(mut validators: TributaryValidatorSet) -> NewSetInformation {
  validators.init_participant_indexes();

  let new_set = NewSetInformation {
    set: random_validator_set(&mut OsRng),
    serai_block: random_bytes_32(&mut OsRng),
    declaration_time: OsRng.next_u64(),
    tributary_validators: validators,
  };
  new_set
}

/// A default [`NewSetInformation`] for tests.
pub fn new_test_set_info(mut validators: TributaryValidatorSet) -> NewSetInformation {
  validators.init_participant_indexes();
  let new_set = NewSetInformation {
    set: default_test_validator_set(),
    serai_block: random_bytes_32(&mut OsRng),
    declaration_time: OsRng.next_u64(),
    tributary_validators: validators,
  };
  new_set
}
