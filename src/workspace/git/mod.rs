mod config;
#[cfg(test)]
mod config_tests;
mod discovery;
// Unix-only in step with the host link it queries: without a way to reach another
// machine there is no remote repository to ask about.
#[cfg(unix)]
pub(crate) mod remote;
mod status;
#[cfg(test)]
mod test_support;

pub use self::{
    discovery::{derive_label_from_cwd, git_branch, git_space_metadata, GitSpaceMetadata},
    status::{git_status_cache_key, git_status_snapshot_for_cwd, GitStatusCacheEntry},
};

#[cfg(test)]
pub(super) use self::status::git_ahead_behind;
