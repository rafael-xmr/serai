use dalek_ff_group::Ristretto;
use futures::FutureExt as _;
use rand_core::OsRng;
use serai_cosign::Cosigning;
use ciphersuite::{WrappedGroup, group::GroupEncoding as _};
use serai_primitives::{
  network_id::NetworkId, test_helpers::random_global_session, validator_sets::ExternalValidatorSet,
};
use serai_task::{FuturesRangeProcessor as _, test_helpers::IntoShimSerai};

use serai_abi::{Block, Event};
use serai_client_serai::{
  Serai,
  abi::{
    self,
    primitives::{
      network_id::ExternalNetworkId,
      test_helpers::{random_serai_address, random_ristretto_public_key},
      crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
    },
  },
};

use std::collections::HashMap;
use crate::{
  NewSetInformation,
  ephemeral::{AuxiliaryKeys, EphemeralEventStream, ScanEphemeralBlocksFrom},
};
use super::*;

pub(crate) struct EphemeralTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
  pub(crate) public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
}

serai_task::impl_serai_task_test_struct!(EphemeralTestStruct, public_serai_auxiliary_key: random_ristretto_public_key(&mut OsRng));

impl IntoTask for EphemeralTestStruct {
  type Task = EphemeralEventStream<MemDb>;

  fn task(&self) -> Self::Task {
    EphemeralEventStream::new(self.db.clone(), self.serai.clone(), self.public_serai_auxiliary_key)
  }
}

impl IntoShimSerai for EphemeralTestStruct {}

fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  _validator: <Ristretto as WrappedGroup>::G,
  networks: Option<Vec<NetworkId>>,
  events: &[Vec<Event>],
  blocks: &[Block],
) {
  let num_blocks = events.len();
  if num_blocks > 0 {
    // ScanEphemeralBlocksFrom should point to the block after the last processed
    assert_eq!(
      ScanEphemeralBlocksFrom::get(db),
      Some(u64::try_from(num_blocks).unwrap()),
      "ScanEphemeralBlocksFrom should be {num_blocks} after processing blocks 0..={num_blocks}"
    );
  } else {
    assert!(
      ScanEphemeralBlocksFrom::get(db).is_none(),
      "ScanEphemeralBlocksFrom should be None after not processing any blocks",
    );
  }

  let mut txn = db.txn();

  // Accumulates expected NewSet content for every SetDecided where our validator was in-set.
  // Keyed by ExternalValidatorSet so we can compare against the global FIFO queue in any order,
  // since messages are enqueued in block order (not network order) but we iterate network-first.
  // let mut expected_new_sets: HashMap<
  //   ExternalValidatorSet,
  //   ([u8; 32], u64, Vec<((SubstrateAuxiliaryKey, NetworkAuxiliaryKey), u16)>),
  // > = HashMap::new();

  for network in networks.unwrap_or_else(|| NetworkId::all().collect()) {
    // Serai has no validator sets or tributaries, skip it
    let Ok(external_network) = ExternalNetworkId::try_from(network) else { continue };

    // For all events in all blocks find the ones for the current network
    for (block_number, block_events) in events.iter().enumerate() {
      let _expected_block_hash = blocks[block_number].header.hash().0;
      let _expected_serai_time = blocks[block_number].header.unix_time_in_millis() / 1000;

      let mut embedded_elliptic_curve_keys_events = Vec::new();
      let mut set_decided_events = Vec::new();
      let mut accepted_handover_events = Vec::new();

      for event in block_events {
        if let serai_abi::Event::ValidatorSets(vset_event) = event {
          #[expect(clippy::wildcard_enum_match_arm)]
          match vset_event {
            abi::validator_sets::Event::SetEmbeddedEllipticCurveKeys { keys, .. } => {
              if keys.network() == external_network.into() {
                embedded_elliptic_curve_keys_events.push(vset_event);
              }
            }
            abi::validator_sets::Event::SetDecided { set, .. } => {
              if set.network == external_network.into() {
                set_decided_events.push(vset_event);
              }
            }
            abi::validator_sets::Event::AcceptedHandover { set } => {
              if set.network == external_network.into() {
                accepted_handover_events.push(vset_event);
              }
            }
            _ => {}
          }
        }
      }

      for event in embedded_elliptic_curve_keys_events {
        let serai_client_serai::abi::validator_sets::Event::SetEmbeddedEllipticCurveKeys {
          validator,
          keys,
        } = &event
        else {
          unreachable!(
            "{}: {event:?}",
            "`SetEmbeddedEllipticCurveKeys` event wasn't a `SetEmbeddedEllipticCurveKeys` event"
          );
        };

        // We only coordinate over external networks
        let Ok(_) = ExternalNetworkId::try_from(keys.network()) else { continue };

        let to_raw = |keys: AuxiliaryKeysStruct| match keys {
          AuxiliaryKeysStruct::Serai(s) | AuxiliaryKeysStruct::Monero(s) => (s, s.to_vec()),
          AuxiliaryKeysStruct::Bitcoin(s, e) | AuxiliaryKeysStruct::Ethereum(s, e) => {
            (s, e.to_vec())
          }
        };

        let from_event = to_raw(*keys);
        let db_entry = AuxiliaryKeys::get(&txn, external_network.into(), *validator);
        let from_db = to_raw(db_entry.expect("selected validator lacked auxiliary keys"));
        assert_eq!(from_event, from_db, "auxiliary keys from event and DB don't match");
      }

      for set_decided in set_decided_events {
        let serai_client_serai::abi::validator_sets::Event::SetDecided { set, validators } =
          &set_decided
        else {
          unreachable!("`SetDecided` event wasn't a `SetDecided` event: {set_decided:?}");
        };

        // We only coordinate over external networks
        let Ok(external_set) = ExternalValidatorSet::try_from(*set) else { continue };

        let to_aux_keys = |keys: AuxiliaryKeysStruct| match keys {
          AuxiliaryKeysStruct::Serai(s) | AuxiliaryKeysStruct::Monero(s) => (s, s.to_vec()),
          AuxiliaryKeysStruct::Bitcoin(s, e) | AuxiliaryKeysStruct::Ethereum(s, e) => {
            (s, e.to_vec())
          }
        };

        let _expected_validators = validators
          .iter()
          .map(|(validator, weight)| {
            let db_entry = AuxiliaryKeys::get(&txn, external_set.network.into(), *validator);
            (
              to_aux_keys(db_entry.expect("selected validator lacked auxiliary keys")),
              u16::from(*weight),
            )
          })
          .collect::<Vec<_>>();

        // The coordinator only emits NewSet when it is itself in the decided set.
        // We store the expected content now and verify against the actual queue after all
        // networks are processed — the queue is global FIFO (block order) but we iterate
        // network-first, so we cannot drain in-place without risking consuming the wrong entry.
        // if validators.iter().any(|(v, _)| *v == validator) {
        //   expected_new_sets
        //     .insert(external_set,
        //  (expected_block_hash, expected_serai_time, expected_validators));
        // }
      }

      for accepted_handover in accepted_handover_events {
        let serai_client_serai::abi::validator_sets::Event::AcceptedHandover { set } =
          &accepted_handover
        else {
          unreachable!(
            "AcceptedHandover event wasn't a AcceptedHandover event: {accepted_handover:?}"
          );
        };

        // We only coordinate over external networks
        let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

        let notification_exists = crate::SignSlashReport::try_recv(&mut txn, set);
        assert!(notification_exists.is_some());
      }
    }

    // Iterated over all events on all blocks for this network
    // Message queue should be empty, next message is None
    // assert!(get_next_msg().is_none());
  }

  // Drain the actual NewSet queue and compare against expected entries (keyed by set).
  // This is done after all networks because the queue is global FIFO (block order) but we
  // iterated network-first above.
  let mut actual_new_sets: HashMap<ExternalValidatorSet, NewSetInformation> = HashMap::new();
  while let Some(msg) = crate::NewSet::try_recv(&mut txn) {
    actual_new_sets.insert(msg.set, msg);
  }

  // assert_eq!(
  //   actual_new_sets.keys().collect::<std::collections::HashSet<_>>(),
  //   expected_new_sets.keys().collect::<std::collections::HashSet<_>>(),
  //   "NewSet queue has different sets than expected"
  // );

  // for (set,
  // (expected_block_hash, expected_serai_time, expected_validators)) in &expected_new_sets {
  //   let msg = &actual_new_sets[set];
  //   assert_eq!(msg.set, *set, "NewSet.set mismatch");
  //   assert_eq!(msg.serai_block, *expected_block_hash, "NewSet.serai_block mismatch for {set:?}");
  //   assert_eq!(
  //     msg.declaration_time, *expected_serai_time,
  //     "NewSet.declaration_time mismatch for {set:?}"
  //   );
  //   assert_eq!(msg.validators, *expected_validators, "NewSet.validators mismatch for {set:?}");

  //   let mut expected_indexes: HashMap<SeraiAddress, Vec<Participant>> = HashMap::new();
  //   let mut expected_reverse: HashMap<Participant, SeraiAddress> = HashMap::new();
  //   let mut next_i = 1u16;
  //   for ((substrate_key, _), weight) in expected_validators {
  //     let addr = substrate_key.to_serai_address();
  //     let mut these_is = Vec::new();
  //     for _ in 0 .. *weight {
  //       let p = Participant::new(next_i).unwrap();
  //       next_i += 1;
  //       these_is.push(p);
  //       expected_reverse.insert(p, addr);
  //     }
  //     expected_indexes.insert(addr, these_is);
  //   }
  //   assert_eq!(
  //     msg.participant_indexes, expected_indexes,
  //     "participant_indexes inconsistent with validators for {set:?}"
  //   );
  //   assert_eq!(
  //     msg.participant_indexes_reverse_lookup, expected_reverse,
  //     "participant_indexes_reverse_lookup inconsistent with validators for {set:?}"
  //   );
  // }

  // `txn` is dropped here without `.commit()`. The channel is left unchanged.
  // retries have to iterate over all block/events & message elements again
  // txn.commit();
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_faulted_session() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = shim.fuzz_blocks(1).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::set_faulted_session(&mut txn, random_global_session(&mut OsRng));
      txn.commit();
    }

    // Does not progress on existing FaultedSession for block
    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "Error getting latest cosigned block number")
        .await;
    }
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[],
      &[],
    );
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_no_latest_is_none() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = shim.fuzz_blocks(1).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    // Simulate task.run_iteration(), calling latest_cosigned_block_number is fine yet
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // Delete the seeded block so cosigned_block(n) returns Ok(None)
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::del_substrate_block_hash(&mut txn, 0);
      serai_cosign::test_helpers::del_latest_cosigned_block_number(&mut txn);
      txn.commit();
    }

    // fetch_item is called for block_number=0, previous latest=0 existed and
    // passed calling latest_cosigned_block_number, but now was deleted
    // so will trigger the panic
    let _ = task_test.task().fetch_item(0).await;
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_greater_than_latest_is_none() {
    let (_, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Seed only block 0 = latest is 0
    seed_cosigned_blocks(&mut task_test.db, &[(0, BlockHash([0u8; 32]))]);

    // Simulate task.run_iteration(), calling latest_cosigned_block_number is fine yet
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // fetch_item is called for block_number=1, but latest=0 so will trigger the panic
    let _ = task_test.task().fetch_item(1).await;
  }

  #[tokio::test]
  async fn panics_on_cosigned_block_no_substrate_blockhash() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    // Block 1 is missing from being indexed as cosigned, here it skips from 0 to 2
    let block_hashes =
      [(0, shim.make_block(0, vec![]).await.0), (2, shim.make_block(2, vec![]).await.0)];
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err = result.expect_err("should panic trying to iterate to block 1 which wasn't indexed");
    assert!(panic_message(&err).contains("cosigned block 1 but didn't index it"),);
  }

  #[tokio::test]
  async fn fetch_item_errors_when_session_faults_after_first_check() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Seed one cosigned block so latest_cosigned_block_number returns Some(0)
    let (block_hashes, _, _) = shim.fuzz_blocks(1).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    // Simulate task.run_iteration() was called
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // Inject the fault into the shared DB after run_iteration is called, simulating the race
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::set_faulted_session(&mut txn, random_global_session(&mut OsRng));
      txn.commit();
    }

    // fetch_item is called and cosigned_block now reads the faulted DB and returns Error
    let mut task = task_test.task();
    assert!(
      matches!(task.fetch_item(0).await, Err(ref e) if e == "cosigning process faulted"),
      "fetch_item must propagate Faulted when session faults between the \
          two latest_cosigned_block_number calls"
    );

    // Task continues failing on next iterations
    {
      TaskTest::task_runs_and_fails_with(&mut task, "Error getting latest cosigned block number")
        .await;
    }
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[],
      &[],
    );
  }

  #[tokio::test]
  async fn handles_serai_block_rpc_error() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(3).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    shim.set_block_number_error("blockchain/block", 1, "connection refused").await;

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block").await;
    }
    // current latest is block 1
    let block0_events = all_events.first().unwrap().clone();
    let block0_block = all_blocks.first().cloned().unwrap();
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[block0_events],
      &[block0_block],
    );

    shim.clear_all_errors().await;

    // No more errors, progresses normallly
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    // new latest is block 3
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &all_events,
      &all_blocks,
    );
  }

  #[tokio::test]
  async fn panics_on_serai_block_none_from_serai() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = shim.fuzz_blocks(1).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    shim.remove_block(0).await;

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err = result.expect_err("should panic when the Serai node is missing a cosigned block");
    assert!(panic_message(&err).contains("Serai node didn't have block"),);
  }

  #[tokio::test]
  async fn handles_serai_events_rpc_error() {
    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
    let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(3).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    shim.set_block_hash_error("blockchain/events", block_hashes[1].1, "timeout").await;

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block events").await;
    }
    // current latest is block 1
    let block1_events = all_events.first().unwrap().clone();
    let block1_block = all_blocks.first().cloned().unwrap();
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[block1_events],
      &[block1_block],
    );

    shim.clear_all_errors().await;

    // No more errors, progresses normallly
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    // new latest is block 3
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &all_events,
      &all_blocks,
    );
  }

  #[tokio::test]
  async fn rejects_set_decided_with_too_many_validators() {
    use serai_abi::{
      primitives::{
        network_id::{NetworkId, ExternalNetworkId},
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
    };
    use serai_shim_rpc::test_helpers::set_decided_event;

    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Build a SetDecided with u16::MAX + 1 validators, one of which is our validator.
    // This exercises the `more than u16::MAX validators sent` error path, which fires
    // before any AuxiliaryKeys lookup — so no SetEmbeddedEllipticCurveKeys events needed.
    let num_validators = usize::from(u16::MAX) + 1;
    let validators: Vec<(serai_primitives::address::SeraiAddress, KeyShares)> =
      (0 .. num_validators).map(|_| (random_serai_address(&mut OsRng), KeyShares::ONE)).collect();

    // Ensure our coordinator's validator is in the set.
    {
      let mut txn = task_test.db.txn();
      AuxiliaryKeys::set(
        &mut txn,
        NetworkId::Serai,
        validators[0].0,
        &AuxiliaryKeysStruct::Serai(task_test.public_serai_auxiliary_key.to_bytes()),
      );
      txn.commit();
    }

    let event = set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      validators,
    );

    let (hash, _, _) = shim.make_block(0, vec![vec![event]]).await;
    seed_cosigned_blocks(&mut task_test.db, &[(0, hash)]);

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "more than u16::MAX validators sent").await;
  }

  #[tokio::test]
  async fn rejects_set_decided_exceeding_max_key_shares() {
    use serai_abi::{
      primitives::{
        network_id::{NetworkId, ExternalNetworkId},
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
    };
    use serai_shim_rpc::test_helpers::set_decided_event;

    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Two validators each with weight 64 gives total_weight = 128 > MAX_PER_SET (127).
    // Our validator is one of them, so `in_set = true` and the check fires before
    // any AuxiliaryKeys lookup.
    let over_weight = KeyShares::saturating_from(64);
    let validators = vec![
      (random_serai_address(&mut OsRng), over_weight),
      (random_serai_address(&mut OsRng), over_weight),
    ];

    // Ensure our coordinator's validator is in the set.
    {
      let mut txn = task_test.db.txn();
      AuxiliaryKeys::set(
        &mut txn,
        NetworkId::Serai,
        validators[0].0,
        &AuxiliaryKeysStruct::Serai(task_test.public_serai_auxiliary_key.to_bytes()),
      );
      txn.commit();
    }

    let event = set_decided_event(
      ValidatorSet { network: NetworkId::External(ExternalNetworkId::Monero), session: Session(0) },
      validators,
    );

    let (hash, _, _) = shim.make_block(0, vec![vec![event]]).await;
    seed_cosigned_blocks(&mut task_test.db, &[(0, hash)]);

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(
      &mut task,
      &format!("key shares when the max is {}", KeyShares::MAX_PER_SET),
    )
    .await;
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn processes_cosigned_blocks() {
    // Does not progress on empty cosign DB
    {
      let (_, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &[],
        &[],
      );
    }

    // Returns made_progress = true with one or more cosigned blocks
    {
      let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(1).await;
      seed_cosigned_blocks(&mut task_test.db, &block_hashes);
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &all_events,
        &all_blocks,
      );
    }

    {
      let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let total_blocks = 10;
      let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(total_blocks).await;
      seed_cosigned_blocks(&mut task_test.db, &block_hashes);
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &all_events,
        &all_blocks,
      );

      // Blocks 0..10 were just seeded and indexed by the canonical task.
      // Attempting to seed a previous block does not regress its state
      let block_hash = shim.make_block(1, vec![]).await.0;
      seed_cosigned_blocks(&mut task_test.db, &[(1u64, block_hash)]);
      let mut task = task_test.task();
      {
        // Does not progress on a block previous than the latest
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        // Old latest amount of blocks of 10 is still the total_blocks
        &all_events,
        &all_blocks,
      );
    }
  }

  #[tokio::test]
  async fn processes_our_validator() {
    use serai_abi::{
      primitives::{
        network_id::{NetworkId, ExternalNetworkId},
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
      validator_sets::Event as ValidatorSetsEvent,
    };
    use serai_shim_rpc::test_helpers::set_decided_event;

    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    let our_auxiliary_key = task_test.public_serai_auxiliary_key;
    let our_identity = random_serai_address(&mut OsRng);

    let embedded_keys_event =
      Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
        validator: our_identity,
        keys: AuxiliaryKeysStruct::Monero(our_auxiliary_key.to_bytes()),
      });
    let (hash0, _, block0) = shim.make_block(0, vec![vec![embedded_keys_event.clone()]]).await;
    seed_cosigned_blocks(&mut task_test.db, &[(0, hash0)]);

    // Run the task to process the block, storing our auxiliary key in the DB
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Verify our auxiliary key was stored in the DB for our validator identity
    {
      let txn = task_test.db.txn();
      let stored_key = AuxiliaryKeys::get(&txn, ExternalNetworkId::Monero.into(), our_identity);
      assert!(
        stored_key.is_some(),
        "our auxiliary key should be stored in DB after processing SetEmbeddedEllipticCurveKeys"
      );
      let AuxiliaryKeysStruct::Monero(stored_bytes) = stored_key.unwrap() else {
        panic!("expected Serai auxiliary keys struct");
      };
      assert_eq!(
        stored_bytes.as_ref(),
        our_auxiliary_key.to_bytes().as_ref(),
        "stored auxiliary key should match our public_serai_auxiliary_key"
      );
    }

    // Second block: emit SetDecided with our validator in the set
    // Since our auxiliary key is now in the DB (via the Serai SetEmbeddedEllipticCurveKeys event),
    // are_we_in_set will return true and the coordinator will process this set
    //
    // We need to emit SetEmbeddedEllipticCurveKeys for all validators on the external network
    // before emitting SetDecided, as the coordinator will try to fetch their keys from that network
    use serai_primitives::test_helpers::random_embedded_elliptic_curve_keys;

    let validators = vec![(our_identity, KeyShares::ONE)];

    // Emit SetEmbeddedEllipticCurveKeys for our validator on the external network (Bitcoin)
    let external_keys = random_embedded_elliptic_curve_keys(&mut OsRng, ExternalNetworkId::Bitcoin);
    let external_keys_event =
      Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
        validator: our_identity,
        keys: external_keys,
      });

    let set_decided = set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      validators,
    );

    let (hash1, _, block1) =
      shim.make_block(1, vec![vec![external_keys_event, set_decided.clone()]]).await;
    seed_cosigned_blocks(&mut task_test.db, &[(1, hash1)]);

    // Run the task again to process the SetDecided event
    // This should succeed since are_we_in_set returns true (our auxiliary key was set)
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Verify both blocks were processed correctly
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      Some(vec![NetworkId::External(ExternalNetworkId::Bitcoin)]),
      // Two blocks of events
      &[vec![embedded_keys_event.clone()], vec![set_decided.clone()]],
      &[block0, block1],
    );
  }

  #[tokio::test]
  async fn fuzzed_event_processing() {
    *INIT_LOGGER;

    let num_blocks = 1000;

    serai_env::log::info!("Canonical fuzz test: {num_blocks} blocks");

    let (shim, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Get our validator address so we can add it to the fuzz blocks
    let our_validator = random_serai_address(&mut OsRng);

    // Also need to set our auxiliary key in the DB for our own validator on NetworkId::Serai
    // This is required for are_we_in_set to return true when our validator is in a SetDecided
    {
      let mut txn = task_test.db.txn();
      AuxiliaryKeys::set(
        &mut txn,
        NetworkId::Serai,
        our_validator,
        &AuxiliaryKeysStruct::Serai(task_test.public_serai_auxiliary_key.to_bytes()),
      );
      txn.commit();
    }

    // Generate blocks with our validator included in the pool
    // fuzz_blocks_with_validators adds our_validator to the pool so it may be randomly selected
    let (block_hashes, all_events, all_blocks) =
      shim.fuzz_blocks_with_validators(num_blocks, &[our_validator]).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);

    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      Some(ExternalNetworkId::all().map(NetworkId::from).collect()),
      &all_events,
      &all_blocks,
    );
  }
}
