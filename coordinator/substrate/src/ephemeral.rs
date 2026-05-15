use std::collections::HashMap;
use core::future::Future;
use std::sync::Arc;
use ciphersuite::{WrappedGroup, group::GroupEncoding as _};
use dalek_ff_group::Ristretto;

use serai_client_serai::{
  abi::primitives::{
    BlockHash,
    crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
    validator_sets::{KeyShares, ExternalValidatorSet},
  },
  Serai,
};

use serai_db::*;
use serai_primitives::{
  crypto::{TributaryValidatorSet, TributaryValidator},
};
use serai_task::{ContinuallyRan, FuturesRangeProcessor};

use serai_cosign::Cosigning;

use crate::NewSetInformation;

create_db!(
  CoordinatorSubstrateEphemeral {
    ScanEphemeralBlocksFrom: () -> u64,
  }
);

/// These are all the events which generate canonical messages
pub struct EphemeralEvents {
  block_hash: BlockHash,
  time: u64,
  set_decided_events: Vec<serai_client_serai::abi::validator_sets::Event>,
  accepted_handover_events: Vec<serai_client_serai::abi::validator_sets::Event>,
}

/// The event stream for ephemeral events.
pub struct EphemeralEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
  public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
}

impl<D: Db> EphemeralEventStream<D> {
  /// Create a new ephemeral event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(
    db: D,
    serai: Arc<Serai>,
    public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
  ) -> Self {
    Self { db, serai, public_serai_auxiliary_key }
  }
}

impl<D: Db> ContinuallyRan for EphemeralEventStream<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let Some(latest_cosigned_block_number) =
        Cosigning::<D>::latest_cosigned_block_number(&self.db)
          // Errors if Faulted session exists and keeps re-trying this task
          // protocol will be halted not able to progress
          .map_err(|e| format!("Error getting latest cosigned block number: {e:?}"))?
      else {
        return Ok(false);
      };

      let start_scan_block_number = ScanEphemeralBlocksFrom::get(&self.db).unwrap_or(0);
      self.process_range(start_scan_block_number, latest_cosigned_block_number).await
    }
  }
}

impl<D: Db> FuturesRangeProcessor for EphemeralEventStream<D> {
  type Item = EphemeralEvents;
  // Sync the next set of upcoming blocks all at once to minimize latency
  const ITEMS_TO_PROCESS_AT_ONCE: u64 = 50;

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
          panic!(
            "iterating to latest cosigned block but couldn't get \
             cosigned block number {block_number}"
          )
        }
        Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_owned()),
      };

      let serai_block = serai
        .block(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block #{block_hash}: {e}"))?
        .unwrap_or_else(|| {
          // If latest_cosigned_block_number returned this block number
          // as cosigned and we iterated to it then it must exist on serai
          panic!(
            "Serai node didn't have block #{block_number} which should've been finalized and \
             cosigned"
          )
        });

      let events = serai
        .events(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block events #{block_hash}: {e}"))?;
      let validator_sets_events = events.validator_sets();
      let set_decided_events =
        validator_sets_events.set_decided_events().cloned().collect::<Vec<_>>();
      let accepted_handover_events =
        validator_sets_events.accepted_handover_events().cloned().collect::<Vec<_>>();

      // We use time in seconds, not milliseconds, here
      let time = serai_block.header.unix_time_in_millis() / 1000;
      Ok((
        block_number,
        EphemeralEvents { block_hash, time, set_decided_events, accepted_handover_events },
      ))
    }
  }

  fn process_item(&mut self, block_number: u64, block: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();

    for set_decided in block.set_decided_events {
      let serai_client_serai::abi::validator_sets::Event::SetDecided { set, validators } =
        &set_decided
      else {
        unreachable!("`SetDecided` event wasn't a `SetDecided` event: {set_decided:?}");
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

      if u16::try_from(validators.len()).is_err() {
        Err("more than u16::MAX validators sent")?;
      }

      let validators = validators
        .iter()
        .map(|(validator, weight)| (*validator, u16::from(*weight)))
        .collect::<Vec<_>>();

      let mut are_we_in_set = false;
      let mut auxiliary_key_validators = Vec::with_capacity(validators.len());
      // Fetch all of the validators' auxiliary keys
      for (validator, weight) in &validators {
        let auxiliary_keys = match serai_cosign::AuxiliaryKeys::get(&txn, set.network, *validator)
          .expect("selected validator lacked auxiliary keys")
        {
          AuxiliaryKeysStruct::Serai(_) => {
            unreachable!("We only coordinate over external networks")
          }
          AuxiliaryKeysStruct::Bitcoin(substrate, external) |
          AuxiliaryKeysStruct::Ethereum(substrate, external) => (substrate, external.to_vec()),
          AuxiliaryKeysStruct::Monero(substrate) => (substrate, substrate.to_vec()),
        };

        let (public_substrate_auxiliary_key, _) = &auxiliary_keys;
        if public_substrate_auxiliary_key[0] == self.public_serai_auxiliary_key.to_bytes()[0] {
          are_we_in_set = true;
        }

        auxiliary_key_validators.push(TributaryValidator {
          substrate_key: *public_substrate_auxiliary_key,
          network_key: auxiliary_keys.1,
          weight: *weight,
        });
      }

      if are_we_in_set {
        // Do the summation in u32 so we don't risk a u16 overflow
        let total_weight = validators.iter().map(|(_, weight)| u32::from(*weight)).sum::<u32>();
        if total_weight > u32::from(KeyShares::MAX_PER_SET) {
          Err(format!(
            "{set:?} has {total_weight} key shares when the max is {}",
            KeyShares::MAX_PER_SET
          ))?;
        }

        let mut tributary_validators = TributaryValidatorSet {
          validators: auxiliary_key_validators,
          participant_indexes: HashMap::new(),
          participant_indexes_reverse_lookup: HashMap::new(),
        };
        tributary_validators.init_participant_indexes();

        let new_set = NewSetInformation {
          set,
          serai_block: block.block_hash.0,
          declaration_time: block.time,
          tributary_validators,
        };
        // These aren't serialized, and we immediately serialize and drop this, so this isn't
        // necessary. It's just good practice not have this be dirty
        crate::NewSet::send(&mut txn, &new_set);
      }
    }

    for accepted_handover in block.accepted_handover_events {
      let serai_client_serai::abi::validator_sets::Event::AcceptedHandover { set } =
        &accepted_handover
      else {
        unreachable!(
          "AcceptedHandover event wasn't a AcceptedHandover event: {accepted_handover:?}"
        );
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      crate::SignSlashReport::send(&mut txn, set);
    }

    ScanEphemeralBlocksFrom::set(&mut txn, &(block_number + 1));
    txn.commit();
    Ok(())
  }
}
