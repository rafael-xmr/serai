//! Common test utilities for [`ContinuallyRan`] tasks.

use crate::ContinuallyRan;

/// Test helpers for asserting task iteration behavior.
pub struct TaskTest;

impl TaskTest {
  /// Assert that a task iteration succeeds and returns the expected progress value.
  pub async fn task_runs_once_and_matches_progress<T: ContinuallyRan>(
    task: &mut T,
    made_progress: bool,
  ) {
    log::debug!("running task once: {}", core::any::type_name::<T>());
    assert_eq!(task.run_iteration().await.unwrap(), made_progress);
  }

  /// Assert that a task iteration fails with an error containing the given string.
  // TODO: Replace this with typed errors.
  pub async fn task_runs_and_fails_with<T: ContinuallyRan>(task: &mut T, error: &str) {
    log::debug!("running task (expecting failure): {}", core::any::type_name::<T>());
    let err = task.run_iteration().await.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(err_str.contains(error), "{err_str}");
  }
}

use core::future::Future;
extern crate alloc;
use alloc::sync::Arc;

/// Shared state used by Serai task tests.
pub struct SeraiTaskTestState {
  /// Serai client used by the task under test.
  pub serai: Arc<serai_client_serai::Serai>,

  /// In-memory database used by the test.
  pub db: serai_db::MemDb,
}

/// Trait for test structs that can be built from Serai test state.
pub trait SeraiTaskTestStruct: Sized {
  /// Build this test struct from the shared Serai test state.
  fn from_state(state: SeraiTaskTestState) -> Self;
}

/// Trait for test structs that can produce a [`ContinuallyRan`] task.
pub trait IntoTask: SeraiTaskTestStruct {
  /// The task type produced by this test struct.
  type Task: 'static + ContinuallyRan;

  /// Create the task from this test struct.
  fn task(&self) -> Self::Task;
}

/// Trait for test structs that use a shim Serai RPC.
pub trait IntoShimSerai: IntoTask {
  /// Create a [`SeraiShimRpc`], this test struct, and its task.
  fn setup_mock_test() -> impl Future<Output = (serai_shim_rpc::SeraiShimRpc, Self)> + Send
  where
    Self: Sized + Send,
  {
    async {
      let (shim, serai) = serai_shim_rpc::SeraiShimRpc::setup_shim_serai().await;
      let test = Self::from_state(SeraiTaskTestState { serai, db: serai_db::MemDb::new() });
      (shim, test)
    }
  }
}

/// Implements [`SeraiTaskTestStruct`] for a struct with `serai` and `db` fields.
///
/// An optional second argument accepts additional `field: expr` pairs for structs
/// with extra fields beyond `serai` and `db`.
#[macro_export]
macro_rules! impl_serai_task_test_struct {
  ($ty:ty) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { serai: state.serai, db: state.db }
      }
    }
  };
  ($ty:ty, $($field:ident: $default:expr),+) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { serai: state.serai, db: state.db, $($field: $default),+ }
      }
    }
  };
  ($ty:ty, { $($field:ident: $src:ident),+ $(,)? }) => {
    impl $crate::test_helpers::SeraiTaskTestStruct for $ty {
      fn from_state(state: $crate::test_helpers::SeraiTaskTestState) -> Self {
        Self { $($field: state.$src),+ }
      }
    }
  };
}
