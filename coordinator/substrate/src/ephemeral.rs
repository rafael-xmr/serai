use core::future::Future;
use std::sync::Arc;

use serai_client_serai::{
  abi::primitives::{
    BlockHash,
    crypto::EmbeddedEllipticCurveKeys as EmbeddedEllipticCurveKeysStruct,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{KeyShares, ExternalValidatorSet},
    address::SeraiAddress,
  },
  Serai,
};

use serai_db::*;
use serai_task::{ContinuallyRan, RangeProcessor};

use serai_cosign::Cosigning;

use crate::NewSetInformation;

create_db!(
  CoordinatorSubstrateEphemeral {
    NextBlock: () -> u64,
    EmbeddedEllipticCurveKeys: (
      network: ExternalNetworkId,
      validator: SeraiAddress
    ) -> EmbeddedEllipticCurveKeysStruct,
  }
);

/// These are all the events which generate canonical messages
pub struct EphemeralEvents {
  block_hash: BlockHash,
  time: u64,
  embedded_elliptic_curve_keys_events: Vec<serai_client_serai::abi::validator_sets::Event>,
  set_decided_events: Vec<serai_client_serai::abi::validator_sets::Event>,
  accepted_handover_events: Vec<serai_client_serai::abi::validator_sets::Event>,
}

/// The event stream for ephemeral events.
pub struct EphemeralEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
  validator: SeraiAddress,
}

impl<D: Db> EphemeralEventStream<D> {
  /// Create a new ephemeral event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(db: D, serai: Arc<Serai>, validator: SeraiAddress) -> Self {
    Self { db, serai, validator }
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

impl<D: Db> RangeProcessor for EphemeralEventStream<D> {
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
      let embedded_elliptic_curve_keys_events = validator_sets_events
        .set_embedded_elliptic_curve_keys_events()
        .cloned()
        .collect::<Vec<_>>();
      let set_decided_events =
        validator_sets_events.set_decided_events().cloned().collect::<Vec<_>>();
      let accepted_handover_events =
        validator_sets_events.accepted_handover_events().cloned().collect::<Vec<_>>();

      // We use time in seconds, not milliseconds, here
      let time = serai_block.header.unix_time_in_millis() / 1000;
      Ok((
        block_number,
        EphemeralEvents {
          block_hash,
          time,
          embedded_elliptic_curve_keys_events,
          set_decided_events,
          accepted_handover_events,
        },
      ))
    }
  }

  fn process_item(&mut self, _block_number: u64, block: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();

    for event in block.embedded_elliptic_curve_keys_events {
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

      match keys.network() {
        NetworkId::Serai => {}
        NetworkId::External(network) => {
          EmbeddedEllipticCurveKeys::set(&mut txn, network, *validator, keys);
        }
      }
    }

    for set_decided in block.set_decided_events {
      let serai_client_serai::abi::validator_sets::Event::SetDecided { set, validators } =
        &set_decided
      else {
        unreachable!("`SetDecided` event wasn't a `SetDecided` event: {set_decided:?}");
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      let validators = validators
        .iter()
        .map(|(validator, weight)| (*validator, u16::from(*weight)))
        .collect::<Vec<_>>();

      let in_set = validators.iter().any(|(validator, _)| *validator == self.validator);
      if in_set {
        if u16::try_from(validators.len()).is_err() {
          Err("more than u16::MAX validators sent")?;
        }

        // Do the summation in u32 so we don't risk a u16 overflow
        let total_weight = validators.iter().map(|(_, weight)| u32::from(*weight)).sum::<u32>();
        if total_weight > u32::from(KeyShares::MAX_PER_SET) {
          Err(format!(
            "{set:?} has {total_weight} key shares when the max is {}",
            KeyShares::MAX_PER_SET
          ))?;
        }
        let total_weight = u16::try_from(total_weight)
          .expect("value smaller than `u16` constant but doesn't fit in `u16`");

        // Fetch all of the validators' embedded elliptic curve keys
        let mut evrf_public_keys = Vec::with_capacity(usize::from(total_weight));
        for (validator, weight) in &validators {
          let keys = match EmbeddedEllipticCurveKeys::get(&txn, set.network, *validator)
            .expect("selected validator lacked embedded elliptic curve keys")
          {
            EmbeddedEllipticCurveKeysStruct::Serai(_) => {
              panic!(
                "
                    requested embedded elliptic curve keys for external network yet received `Serai`
                  "
              )
            }
            EmbeddedEllipticCurveKeysStruct::Bitcoin(substrate, external) => {
              assert_eq!(set.network, ExternalNetworkId::Bitcoin);
              (substrate, external.to_vec())
            }
            EmbeddedEllipticCurveKeysStruct::Ethereum(substrate, external) => {
              assert_eq!(set.network, ExternalNetworkId::Ethereum);
              (substrate, external.to_vec())
            }
            EmbeddedEllipticCurveKeysStruct::Monero(substrate) => {
              assert_eq!(set.network, ExternalNetworkId::Monero);
              (substrate, substrate.to_vec())
            }
          };
          for _ in 0 .. *weight {
            evrf_public_keys.push(keys.clone());
          }
        }

        let mut new_set = NewSetInformation {
          set,
          serai_block: block.block_hash.0,
          declaration_time: block.time,
          // TODO: This should be inlined into the Processor's key gen code
          // It's legacy from when we removed participants from the key gen
          threshold: ((total_weight * 2) / 3) + 1,
          // TODO: Why are `validators` and `evrf_public_keys` two separate fields?
          validators,
          evrf_public_keys,
          participant_indexes: Default::default(),
          participant_indexes_reverse_lookup: Default::default(),
        };
        // These aren't serialized, and we immediately serialize and drop this, so this isn't
        // necessary. It's just good practice not have this be dirty
        new_set.init_participant_indexes();
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

      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      crate::SignSlashReport::send(&mut txn, set);
    }

    txn.commit();
    Ok(())
  }
}
