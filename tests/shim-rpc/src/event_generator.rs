use serai_primitives::validator_sets::Session;

pub mod in_instructions_events {
  use rand_core::{RngCore, CryptoRng};
  use serai_abi::{Event, primitives::network_id::ExternalNetworkId};
  use serai_primitives::test_helpers::random_block_hash;
  use super::Session;
  use bitvec::vec::BitVec as Bv;
  use serai_primitives::BitVec;

  pub fn batch<R: RngCore + CryptoRng>(
    rng: &mut R,
    network: ExternalNetworkId,
    publishing_session: Session,
    id: u32,
  ) -> Event {
    let num_results = usize::try_from(rng.next_u64() % 20).unwrap();
    let mut bits = Bv::with_capacity(num_results);
    for _ in 0 .. num_results {
      bits.push(rng.next_u64() % 2 == 0);
    }

    Event::InInstructions(serai_abi::in_instructions::Event::Batch {
      network,
      publishing_session,
      id,
      external_network_block_hash: random_block_hash(rng),
      in_instructions_hash: random_block_hash(rng).0,
      in_instruction_results: BitVec::try_from(bits).unwrap(),
    })
  }
}
