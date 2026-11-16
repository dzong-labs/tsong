//! Config from Git: [`GitStore`] reads the config from a branch, and
//! [`webhook`] verifies the Git host's push notifications.

mod store;
pub mod webhook;

pub use store::{GitStore, ssh_command};
