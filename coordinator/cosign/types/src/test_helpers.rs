use rand_core::{RngCore, CryptoRng};

use serai_primitives::test_helpers::{random_block_hash, random_global_session};

use crate::{CosignIntent, Cosign, SignedCosign};

/// Sign a [`Cosign`] with a schnorrkel keypair, producing a [`SignedCosign`].
pub fn sign_cosign(cosign: Cosign, keypair: &schnorrkel::Keypair) -> SignedCosign {
  SignedCosign {
    signature: keypair.sign_simple(crate::COSIGN_CONTEXT, &cosign.signature_message()).to_bytes(),
    cosign,
  }
}

/// Generate a random [`Cosign`] for testing.
pub fn random_cosign(rng: &mut (impl RngCore + CryptoRng)) -> Cosign {
  Cosign {
    global_session: random_global_session(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    cosigner: serai_primitives::test_helpers::random_external_network_id(rng),
  }
}

/// Generate a random [`CosignIntent`] for testing.
pub fn random_cosign_intent(rng: &mut (impl RngCore + CryptoRng)) -> CosignIntent {
  CosignIntent {
    global_session: random_global_session(rng),
    block_number: rng.next_u64(),
    block_hash: random_block_hash(rng),
    notable: rng.next_u32() % 2 == 0,
  }
}
