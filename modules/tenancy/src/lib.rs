//! Tenancy management: users, teams, and their role bindings on SBOM groups.
//!
//! This module is intended to be driven by an external orchestration platform, which holds the
//! `manage.tenancy` permission.

pub mod api_key;
pub mod audit;
pub mod audit_log;
pub mod authz;
pub mod binding;
pub mod email;
pub mod endpoints;
pub mod error;
pub mod group;
pub mod me;
pub mod principal;
pub mod scope;
pub mod team;
pub mod user;

#[cfg(test)]
mod test;

pub use error::Error;
