//! Filesystem path helpers shared by the linter pipeline and the CLI.
//!
//! The linter must decide, in several places, whether a candidate path is
//! still "inside" a user-supplied root even in the presence of `..`
//! components, dangling symlinks, or symlink targets that escape the root.
//! Doing this correctly requires a mix of physical canonicalization (when
//! the filesystem cooperates) and a lexical fallback (when it does not).
//! These helpers factor that logic out so every caller uses the same rules.

use std::path::{Component, Path, PathBuf};

/// Lexically normalize `path` by dropping `.` components and collapsing `..`
/// against preceding `Normal` components.
///
/// Purely syntactic — no filesystem access. Callers that also need physical
/// resolution must call [`Path::canonicalize`] themselves; this helper is the
/// fallback when canonicalization fails (dangling symlink, unreadable
/// directory, etc.).
pub fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    normalized
}

/// True when reading `link` as a symlink yields a target that resolves
/// outside `canonical_root`.
///
/// `canonical_root` must already have been passed through
/// [`Path::canonicalize`] — the helper is called from hot loops where the
/// caller has that value on hand. A `read_link` failure returns `false`
/// (the caller has already committed to treating `link` as safe by that
/// point). Both an absolute and a relative symlink target are handled; a
/// relative target is joined against the link's parent directory before
/// comparison. When canonicalization of the target fails, [`normalize_path`]
/// provides the lexical fallback.
pub fn symlink_target_outside_root(canonical_root: &Path, link: &Path) -> bool {
    let Ok(target) = std::fs::read_link(link) else {
        return false;
    };
    let target = if target.is_absolute() {
        target
    } else {
        let base = link.parent().unwrap_or_else(|| Path::new("."));
        let base = if base.is_absolute() {
            base.to_path_buf()
        } else {
            match std::env::current_dir() {
                Ok(current_dir) => current_dir.join(base),
                Err(_) => return false,
            }
        };
        base.join(target)
    };
    if let Ok(target) = target.canonicalize() {
        return !target.starts_with(canonical_root);
    }
    !normalize_path(target).starts_with(canonical_root)
}
