use std::sync::{Arc, LazyLock};

use serai_db::{Db as _, DbTxn as _, MemDb};
use serai_env::panic_message;
use serai_primitives::BlockHash;
pub(crate) use serai_task::test_helpers::{IntoTask, TaskTest};

#[cfg(test)]
mod canonical;

#[cfg(test)]
mod ephemeral;

static INIT_LOGGER: LazyLock<()> = LazyLock::new(|| {
  serai_env::init_logger();
});

/// Populate the cosigning DB so that `Cosigning::latest_cosigned_block_number` returns
/// the max block number and `Cosigning::cosigned_block(n)` returns the correct hash
/// for each block in the list.
pub(crate) fn seed_cosigned_blocks(db: &mut MemDb, block_hashes: &[(u64, BlockHash)]) {
  let mut txn = db.txn();
  for &(number, hash) in block_hashes {
    serai_cosign::test_helpers::set_substrate_block_hash(&mut txn, number, &hash);
  }
  if let Some(&(max_number, _)) = block_hashes.last() {
    serai_cosign::test_helpers::set_latest_cosigned_block_number(&mut txn, max_number);
  }
  txn.commit();
}
