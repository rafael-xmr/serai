use core::future::Future;
use std::sync::Arc;

use serai_client_serai::{
  abi::{self, primitives::network_id::ExternalNetworkId, validator_sets::ReportedSlashes},
  Serai,
};

use messages::substrate::{InInstructionResult, ExecutedBatch, CoordinatorMessage};

use serai_db::*;
use serai_task::{ContinuallyRan, RangeProcessor};

use serai_cosign::Cosigning;

create_db!(
  CoordinatorSubstrateCanonical {
    ScanCanonicalBlocksFrom: () -> u64,
    LastIndexedBatchId: (network: ExternalNetworkId) -> u32,
  }
);

/// These are all the events which generate canonical messages
pub struct CanonicalEvents {
  time: u64,
  set_keys_events: Vec<abi::validator_sets::Event>,
  slash_report_events: Vec<abi::validator_sets::Event>,
  batch_events: Vec<abi::in_instructions::Event>,
  burn_events: Vec<abi::coins::Event>,
}

/// The event stream for canonical events.
pub struct CanonicalEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
}

impl<D: Db> CanonicalEventStream<D> {
  /// Create a new canonical event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(db: D, serai: Arc<Serai>) -> Self {
    Self { db, serai }
  }
}

impl<D: Db> ContinuallyRan for CanonicalEventStream<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let Some(latest_cosigned_block_number) =
        Cosigning::<D>::latest_cosigned_block_number(&self.db).map_err(|e| format!("{e:?}"))?
      else {
        return Ok(false);
      };

      let start_scan_block_number = ScanCanonicalBlocksFrom::get(&self.db).unwrap_or(0);

      self.process_range(start_scan_block_number, latest_cosigned_block_number).await
    }
  }
}

impl<D: Db> RangeProcessor for CanonicalEventStream<D> {
  type Item = CanonicalEvents;
  const ITEMS_TO_PROCESS_AT_ONCE: u64 = 10;

  // For a cosigned block, fetch all relevant events
  fn fetch_item(
    &self,
    block_number: u64,
  ) -> impl Send + 'static + Future<Output = Result<(u64, Self::Item), Self::Error>> {
    let db = self.db.clone();
    let serai = self.serai.clone();
    async move {
      let block_hash = Cosigning::<D>::cosigned_block(&db, block_number);
      let block_hash = match block_hash {
        Ok(Some(block_hash)) => block_hash,
        Ok(None) => {
          panic!("iterating to latest cosigned block but couldn't get cosigned block")
        }
        Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_owned()),
      };
      let events = serai.events(block_hash).await.map_err(|e| format!("{e}"))?;
      let validator_sets_events = events.validator_sets();
      let set_keys_events = validator_sets_events.set_keys_events().cloned().collect();
      let slash_report_events = validator_sets_events.slashes_events().cloned().collect();
      let batch_events = events.in_instructions().batch_events().cloned().collect();
      let burn_events = events.coins().burn_with_instruction_events().cloned().collect();
      let Some(block) = serai.block(block_hash).await.map_err(|e| format!("{e:?}"))? else {
        Err(format!("Serai node didn't have cosigned block #{block_number}"))?
      };

      // We use time in seconds, not milliseconds, here
      let time = block.header.unix_time_in_millis() / 1000;
      Ok((
        block_number,
        CanonicalEvents { time, set_keys_events, slash_report_events, batch_events, burn_events },
      ))
    }
  }

  fn process_item(&mut self, block_number: u64, block: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();

    for set_keys in block.set_keys_events {
      let abi::validator_sets::Event::SetKeys { set, key_pair } = &set_keys else {
        unreachable!("`SetKeys` event wasn't a `SetKeys` event: {set_keys:?}");
      };
      crate::Canonical::send(
        &mut txn,
        set.network,
        &CoordinatorMessage::SetKeys {
          serai_time: block.time,
          session: set.session,
          key_pair: key_pair.clone(),
        },
      );
    }

    for slash_report in block.slash_report_events {
      // TODO: This assumes this is always reported on set close but that isn't the case. We
      // need to shim this event if the report isn't published in a timely fashion.
      let abi::validator_sets::Event::Slashes(reported_slashes) = &slash_report else {
        unreachable!("`Slashes` event wasn't a `Slashes` event: {slash_report:?}");
      };
      match reported_slashes {
        ReportedSlashes::SeraiValidator(_) => {}
        ReportedSlashes::ExternalValidatorSet(set) => {
          crate::Canonical::send(
            &mut txn,
            set.network,
            &CoordinatorMessage::SlashesReported { session: set.session },
          );
        }
      }
    }

    for network in ExternalNetworkId::all() {
      let mut batch = None;
      for this_batch in &block.batch_events {
        // Only irrefutable as this is the only member of the enum at this time
        #[expect(irrefutable_let_patterns)]
        let abi::in_instructions::Event::Batch {
          network: batch_network,
          publishing_session,
          id,
          external_network_block_hash,
          in_instructions_hash,
          in_instruction_results,
        } = this_batch
        else {
          unreachable!("Batch event wasn't a Batch event: {this_batch:?}");
        };
        if network == *batch_network {
          if batch.is_some() {
            Err("Serai block had multiple batches for the same network".to_owned())?;
          }
          batch =
            Some(ExecutedBatch {
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
            });

          assert_eq!(
            LastIndexedBatchId::get(&txn, network),
            id.checked_sub(1),
            "next batch from Serai's ID was not an increment of the last indexed batch's ID"
          );
          LastIndexedBatchId::set(&mut txn, network, id);
        }
      }

      let mut burns = vec![];
      for burn in &block.burn_events {
        let abi::coins::Event::BurnWithInstruction { from: _, instruction } = &burn else {
          unreachable!("BurnWithInstruction event wasn't a BurnWithInstruction event: {burn:?}")
        };
        if instruction.balance.coin.network() == network {
          burns.push(instruction.clone());
        }
      }

      crate::Canonical::send(
        &mut txn,
        network,
        &CoordinatorMessage::Block { serai_block_number: block_number, batch, burns },
      );
    }

    ScanCanonicalBlocksFrom::set(&mut txn, &(block_number + 1));
    txn.commit();
    Ok(())
  }
}

pub(crate) fn last_indexed_batch_id(getter: &impl Get, network: ExternalNetworkId) -> Option<u32> {
  LastIndexedBatchId::get(getter, network)
}
