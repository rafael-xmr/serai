use std::collections::HashMap;
use futures::FutureExt as _;
use rand::RngCore as _;
use rand_core::OsRng;
use serai_cosign::Cosigning;
use serai_primitives::{
  test_helpers::{random_global_session, random_external_network_id},
  validator_sets::Session,
  instructions::OutInstructionWithBalance,
};
use serai_task::{FuturesRangeProcessor as _, test_helpers::IntoShimSerai};
use serai_shim_rpc::event_generator::in_instructions_events;

use serai_abi::{Block, Event, validator_sets::ReportedSlashes};
use serai_client_serai::{
  Serai,
  abi::{self, primitives::network_id::ExternalNetworkId},
};

use crate::{
  Canonical,
  canonical::{CanonicalEventStream, ScanCanonicalBlocksFrom, last_indexed_batch_id},
};
use super::*;

use messages::substrate::{CoordinatorMessage, ExecutedBatch, InInstructionResult};

struct CanonicalTestStruct {
  serai: Arc<Serai>,
  db: MemDb,
}

serai_task::impl_serai_task_test_struct!(CanonicalTestStruct);

impl IntoTask for CanonicalTestStruct {
  type Task = CanonicalEventStream<MemDb>;

  fn task(&self) -> Self::Task {
    CanonicalEventStream::new(self.db.clone(), self.serai.clone())
  }
}

impl IntoShimSerai for CanonicalTestStruct {}

fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  networks: Option<Vec<ExternalNetworkId>>,
  events: &[Vec<Event>],
  blocks: &[Block],
) {
  let num_blocks = events.len();
  if num_blocks > 0 {
    // ScanCanonicalBlocksFrom should point to the block after the last processed
    assert_eq!(
      ScanCanonicalBlocksFrom::get(db),
      Some(u64::try_from(num_blocks).unwrap()),
      "ScanCanonicalBlocksFrom should be {num_blocks} after processing blocks 0..={num_blocks}"
    );
  } else {
    assert!(
      ScanCanonicalBlocksFrom::get(db).is_none(),
      "ScanCanonicalBlocksFrom should be None after not processing any blocks",
    );
  }

  let mut txn = db.txn();
  let mut last_batch_ids = HashMap::new();

  // For each network, start asserting every one of its sent messages
  // messages are stored as a queue per network, every event added
  // is stored one after the other
  for network in &networks.unwrap_or_else(|| ExternalNetworkId::all().collect()) {
    let get_next_msg = |txn: &mut _| Canonical::try_recv(txn, *network);

    // For all events in all blocks find the ones for the current network
    for (block_number, block_events) in events.iter().enumerate() {
      let expected_serai_time = blocks[block_number].header.unix_time_in_millis() / 1000;

      let mut set_keys_events = Vec::new();
      let mut slashes_events = Vec::new();
      let mut batch_event: Option<&serai_abi::in_instructions::Event> = None;
      let mut burns = Vec::new();

      for event in block_events {
        #[expect(clippy::wildcard_enum_match_arm)]
        match event {
          #[expect(clippy::wildcard_enum_match_arm)]
          serai_abi::Event::ValidatorSets(vset_event) => match vset_event {
            abi::validator_sets::Event::SetKeys { set, .. } => {
              if &set.network == network {
                set_keys_events.push(vset_event);
              }
            }
            abi::validator_sets::Event::Slashes(ReportedSlashes::ExternalValidatorSet(set)) => {
              if &set.network == network {
                slashes_events.push(vset_event);
              }
            }
            _ => {}
          },
          serai_abi::Event::InInstructions(this_batch) => {
            let abi::in_instructions::Event::Batch { network: this_network, .. } = this_batch;

            if this_network == network {
              assert!(batch_event.is_none(), "double batch");
              batch_event = Some(this_batch);
            }
          }
          serai_abi::Event::Coins(burn) => {
            let abi::coins::Event::BurnWithInstruction { instruction, .. } = burn else {
              unreachable!("BurnWithInstruction event wasn't a BurnWithInstruction event: {burn:?}")
            };

            if &instruction.balance.coin.network() == network {
              burns.push(event);
            }
          }
          _ => {}
        }
      }

      for set_keys_event in set_keys_events {
        let abi::validator_sets::Event::SetKeys { set, key_pair } = set_keys_event else {
          unreachable!("`SetKeys` event wasn't a `SetKeys` event: {set_keys_event:?}");
        };

        if let Some(CoordinatorMessage::SetKeys { serai_time, session, key_pair: msg_key_pair }) =
          get_next_msg(&mut txn)
        {
          assert_eq!(serai_time, expected_serai_time);
          assert_eq!(session, set.session);
          assert_eq!(msg_key_pair, *key_pair);
        }
      }

      for slash_event in slashes_events {
        let abi::validator_sets::Event::Slashes(reported_slashes) = slash_event else {
          unreachable!("`SetKeys` event wasn't a `SetKeys` event: {slash_event:?}");
        };

        if let Some(CoordinatorMessage::SlashesReported { session }) = get_next_msg(&mut txn) {
          match reported_slashes {
            ReportedSlashes::SeraiValidator(_) => {}
            ReportedSlashes::ExternalValidatorSet(set) => {
              assert_eq!(session, set.session);
            }
          }
        }
      }

      if batch_event.is_some() || !burns.is_empty() {
        if let Some(msg) = get_next_msg(&mut txn) {
          let CoordinatorMessage::Block {
            serai_block_number,
            batch: ref msg_batch,
            burns: ref msg_burns,
          } = msg
          else {
            panic!("");
          };
          assert_eq!(
            serai_block_number,
            u64::try_from(block_number).unwrap(),
            "Block number mismatch for {network:?}"
          );
          let expected_batch = batch_event.map(|be| {
            let abi::in_instructions::Event::Batch {
              id,
              publishing_session,
              external_network_block_hash,
              in_instructions_hash,
              in_instruction_results,
              ..
            } = be;
            last_batch_ids.insert(*network, *id);
            ExecutedBatch {
              id: *id,
              publisher: *publishing_session,
              external_network_block_hash: external_network_block_hash.0,
              in_instructions_hash: *in_instructions_hash,
              in_instruction_results: in_instruction_results
                .iter()
                .map(|bit| {
                  if *bit {
                    InInstructionResult::Succeeded
                  } else {
                    InInstructionResult::Failed
                  }
                })
                .collect(),
            }
          });
          assert_eq!(
            msg_batch, &expected_batch,
            "batch mismatch for {network:?} at block {block_number}"
          );

          let expected_burns: Vec<OutInstructionWithBalance> = burns
            .iter()
            .map(|burn_event| {
              let serai_abi::Event::Coins(abi::coins::Event::BurnWithInstruction {
                instruction,
                ..
              }) = burn_event
              else {
                unreachable!(
                  "BurnWithInstruction event wasn't a BurnWithInstruction event: {burn_event:?}"
                )
              };
              instruction.clone()
            })
            .collect();
          assert_eq!(
            msg_burns, &expected_burns,
            "burns mismatch for {network:?} at block {block_number}"
          );
        }
      }
    }

    assert_eq!(
      &last_indexed_batch_id(&txn, *network).unwrap_or(0),
      last_batch_ids.get(network).unwrap_or(&0)
    );

    // Iterated over all events on all blocks for this network
    // Message queue should be empty, next message is None
    assert!(get_next_msg(&mut txn).is_none());
  }

  // `txn` is dropped here without `.commit()`. The channel is left unchanged.
  // retries have to iterate over all block/events & message elements again
  // txn.commit();
}

/// All test cases where an Error or Panic is returned and the task does not progress
/// (made_progress returns false)
mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_faulted_session() {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_no_latest_is_none() {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    let (_, mut task_test) = CanonicalTestStruct::setup_mock_test().await;

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
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;

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
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  #[tokio::test]
  async fn handles_serai_block_rpc_error() {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  #[tokio::test]
  async fn panics_on_serai_block_none_from_serai() {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
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
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  #[tokio::test]
  async fn panics_on_multiple_batches_per_network_on_block() {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let network = random_external_network_id(&mut OsRng);

    let (block_hash, _, _) = shim
      .add_block_with_events(vec![vec![
        in_instructions_events::batch(&mut OsRng, network, Session(0), 0),
        in_instructions_events::batch(&mut OsRng, network, Session(0), 0),
      ]])
      .await;
    seed_cosigned_blocks(&mut task_test.db, &[(0, block_hash)]);

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err =
      result.expect_err("should panic on multiple batches for same network on the same block");
    assert!(panic_message(&err).contains("Serai block had multiple batches for the same network"));
  }

  #[tokio::test]
  async fn panics_on_next_batch_non_increment() {
    {
      let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);

      let (hash0, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          5,
        )]])
        .await;
      let (hash1, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          10,
        )]])
        .await;
      seed_cosigned_blocks(&mut task_test.db, &[(0, hash0), (1, hash1)]);

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }

    {
      let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);

      let (hash0, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          10,
        )]])
        .await;
      let (hash1, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          5,
        )]])
        .await;
      seed_cosigned_blocks(&mut task_test.db, &[(0, hash0), (1, hash1)]);

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }

    {
      let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);

      let id = OsRng.next_u32();

      let (hash0, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          id,
        )]])
        .await;
      let (hash1, _, _) = shim
        .add_block_with_events(vec![vec![in_instructions_events::batch(
          &mut OsRng,
          network,
          Session(0),
          id,
        )]])
        .await;
      seed_cosigned_blocks(&mut task_test.db, &[(0, hash0), (1, hash1)]);

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }
  }
}

/// Below are all test cases where the task does progress
/// (made_progress returns true)

#[tokio::test]
async fn processes_cosigned_blocks() {
  // Does not progress on empty cosign DB
  {
    let (_, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  // Returns made_progress = true with one or more cosigned blocks
  {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(1).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  {
    let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let total_blocks = 10;
    let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(total_blocks).await;
    seed_cosigned_blocks(&mut task_test.db, &block_hashes);
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);

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
      None,
      // Old latest amount of blocks of 10 is still the total_blocks
      &all_events,
      &all_blocks,
    );
  }
}

#[tokio::test]
async fn fuzzed_event_processing() {
  *INIT_LOGGER;

  let num_blocks = 1000;

  serai_env::log::info!("Canonical fuzz test: {num_blocks} blocks");

  let (shim, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
  let (block_hashes, all_events, all_blocks) = shim.fuzz_blocks(num_blocks).await;
  seed_cosigned_blocks(&mut task_test.db, &block_hashes);

  let mut task = task_test.task();
  {
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  }

  verify_db_invariants_for_network_and_events(
    &mut task_test.db,
    Some(ExternalNetworkId::all().collect()),
    &all_events,
    &all_blocks,
  );
}
