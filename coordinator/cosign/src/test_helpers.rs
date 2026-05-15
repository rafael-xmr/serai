use serai_db::DbTxn;
use crate::{SubstrateBlockHash, delay::LatestCosignedBlockNumber};

/// Seed the DB with the hash for a cosigned Substrate block number.
pub fn set_substrate_block_hash(
  txn: &mut impl DbTxn,
  block_number: u64,
  hash: &serai_client_serai::abi::primitives::BlockHash,
) {
  SubstrateBlockHash::set(txn, block_number, hash);
}

/// Seed the DB with the latest cosigned block number.
pub fn set_latest_cosigned_block_number(txn: &mut impl DbTxn, block_number: u64) {
  LatestCosignedBlockNumber::set(txn, &block_number);
}

/// Seed the DB to mark a global session as faulted.
pub fn set_faulted_session(txn: &mut impl DbTxn, global_session: [u8; 32]) {
  crate::FaultedSession::set(txn, &global_session);
}

/// Delete the hash for a cosigned Substrate block number.
pub fn del_substrate_block_hash(txn: &mut impl DbTxn, block_number: u64) {
  SubstrateBlockHash::del(txn, block_number);
}

/// Delete the latest cosigned block number.
pub fn del_latest_cosigned_block_number(txn: &mut impl DbTxn) {
  LatestCosignedBlockNumber::del(txn);
}
