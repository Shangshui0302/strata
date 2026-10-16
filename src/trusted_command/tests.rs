// SPDX-License-Identifier: MIT

use std::{fs, path::Path};

use super::{SEARCH_ROOTS, TRUST_ROOTS, command, resolve, resolve_in, resolve_with_extra_in};

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("scratch directory")
}

fn write_helper(dir: &Path, name: &str) {
    fs::create_dir_all(dir).expect("create helper directory");
    fs::write(dir.join(name), b"").expect("write helper");
}

fn resolve_same(name: &str, dirs: &[&Path]) -> Result<std::path::PathBuf, String> {
    resolve_in(name, dirs, dirs)
}

#[test]
fn resolve_uses_only_allowlisted_directories() {
    let root = scratch();
    let first = root.path().join("first");
    let second = root.path().join("second");
    let path_dir = root.path().join("path");
    write_helper(&first, "bwrap");
    write_helper(&path_dir, "bwrap");

    let resolved =
        resolve_same("bwrap", &[first.as_path(), second.as_path()]).expect("found bwrap");

    assert_eq!(resolved, first.join("bwrap"));
    assert!(resolved.is_absolute());
    assert_ne!(resolved, path_dir.join("bwrap"));
}

#[test]
fn resolve_rejects_bad_names_and_misses() {
    let root = scratch();
    let empty = root.path().join("empty");
    fs::create_dir_all(&empty).expect("create empty directory");

    for name in ["", ".", "..", "usr/bin/bwrap", "bwrap"] {
        assert!(
            resolve_same(name, &[empty.as_path()]).is_err(),
            "{name:?} must fail closed"
        );
    }
    assert!(resolve_same("bwrap", &[]).is_err());
}

#[test]
fn resolve_requires_final_path_under_a_trusted_directory() {
    let root = scratch();
    let trusted = root.path().join("trusted");
    let outside = root.path().join("outside");
    write_helper(&trusted, "tar");
    write_helper(&outside, "bwrap");
    std::os::unix::fs::symlink(outside.join("bwrap"), trusted.join("bwrap"))
        .expect("helper symlink");

    let accepted = resolve_same("tar", &[trusted.as_path()]).expect("in-allowlist file");
    assert_eq!(accepted, trusted.join("tar"));
    assert!(resolve_same("bwrap", &[trusted.as_path()]).is_err());
}

#[test]
fn resolve_execs_search_path_when_canonical_target_is_in_store() {
    let root = scratch();
    let profile = root.path().join("sw/bin");
    let store = root.path().join("nix/store/hash-bwrap/bin");
    write_helper(&store, "bwrap");
    fs::create_dir_all(&profile).expect("create profile bin");
    std::os::unix::fs::symlink(store.join("bwrap"), profile.join("bwrap"))
        .expect("profile symlink into store");

    let store_root = root.path().join("nix/store");
    let resolved = resolve_in("bwrap", &[profile.as_path()], &[store_root.as_path()])
        .expect("nix profile helper");

    assert_eq!(resolved, profile.join("bwrap"));
    assert_eq!(
        resolved.file_name().and_then(|name| name.to_str()),
        Some("bwrap")
    );
    assert_ne!(
        resolved,
        store.join("bwrap").canonicalize().expect("store target")
    );
}

#[test]
fn configured_helpers_are_fallbacks_after_system_wrappers() {
    let root = scratch();
    let wrappers = root.path().join("wrappers");
    let store = root.path().join("store");
    let first = store.join("first/bin");
    let second = store.join("second/bin");
    write_helper(&wrappers, "bwrap");
    write_helper(&first, "bwrap");
    write_helper(&second, "bwrap");
    let configured = format!("{}:{}", first.display(), second.display());
    let search = &[wrappers.as_path()];
    let trust = &[wrappers.as_path(), store.as_path()];

    assert_eq!(
        resolve_with_extra_in("bwrap", search, trust, Some(&configured))
            .expect("system wrapper takes priority"),
        wrappers.join("bwrap")
    );
    fs::remove_file(wrappers.join("bwrap")).expect("remove wrapper");
    assert!(resolve_with_extra_in("bwrap", search, trust, None).is_err());
    assert_eq!(
        resolve_with_extra_in("bwrap", search, trust, Some(&configured))
            .expect("first configured fallback"),
        first.join("bwrap")
    );
    fs::remove_file(first.join("bwrap")).expect("remove first fallback");
    assert_eq!(
        resolve_with_extra_in("bwrap", search, trust, Some(&configured))
            .expect("second configured fallback"),
        second.join("bwrap")
    );
}

#[test]
fn configured_helpers_reject_untrusted_directories_and_targets() {
    let root = scratch();
    let store = root.path().join("store");
    let outside = root.path().join("outside");
    write_helper(&store, "bwrap");
    write_helper(&outside, "untrusted");
    std::os::unix::fs::symlink(store.join("bwrap"), outside.join("bwrap"))
        .expect("untrusted directory with trusted target");
    std::os::unix::fs::symlink(outside.join("untrusted"), store.join("escape"))
        .expect("trusted directory with untrusted target");
    std::os::unix::fs::symlink(&outside, store.join("escape-dir"))
        .expect("directory symlink outside trust root");

    let cwd = std::env::current_dir().expect("current directory");
    let mut relative = std::path::PathBuf::new();
    for _ in cwd.ancestors().skip(1) {
        relative.push("..");
    }
    relative.push(store.strip_prefix("/").expect("absolute scratch directory"));
    assert!(relative.is_dir());

    for configured in [
        String::new(),
        ":relative:.:..:".to_owned(),
        relative.display().to_string(),
        root.path().join("missing").display().to_string(),
        outside.display().to_string(),
        store.join("escape-dir").display().to_string(),
        store.join("bwrap").display().to_string(),
    ] {
        assert!(
            resolve_with_extra_in("bwrap", &[], &[&store], Some(&configured)).is_err(),
            "reject {configured:?}"
        );
        let fallback = format!("{configured}:{}", store.display());
        assert_eq!(
            resolve_with_extra_in("bwrap", &[], &[&store], Some(&fallback))
                .expect("invalid entry does not hide valid fallback"),
            store.join("bwrap")
        );
    }
    let configured = store.display().to_string();
    for name in ["escape", "missing", "", ".", "..", "../outside/untrusted"] {
        assert!(resolve_with_extra_in(name, &[], &[&store], Some(&configured)).is_err());
    }
}

#[test]
fn configured_directory_alias_cannot_redirect_the_resolved_command() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = scratch();
    let store = root.path().join("store/bin");
    let outside = root.path().join("outside");
    let alias = root.path().join("replaceable-alias");
    write_helper(&store, "multicall");
    fs::write(
        store.join("multicall"),
        b"#!/bin/sh\nprintf 'trusted:%s' \"$0\"\n",
    )
    .expect("write executable helper");
    fs::set_permissions(store.join("multicall"), fs::Permissions::from_mode(0o755))
        .expect("make helper executable");
    symlink("multicall", store.join("bwrap")).expect("multicall helper name");
    write_helper(&outside, "bwrap");
    symlink(&store, &alias).expect("configured directory alias");

    let configured = alias.display().to_string();
    let resolved = resolve_with_extra_in("bwrap", &[], &[&store], Some(&configured))
        .expect("canonical trusted directory");
    assert_eq!(resolved, store.join("bwrap"));
    fs::remove_file(&alias).expect("remove original alias");
    symlink(&outside, &alias).expect("replace alias with untrusted directory");
    let output = std::process::Command::new(&resolved)
        .output()
        .expect("execute original helper");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("helper output"),
        format!("trusted:{}", store.join("bwrap").display())
    );
    assert!(resolve_with_extra_in("bwrap", &[], &[&store], Some(&configured)).is_err());
}

#[test]
fn host_helpers_use_absolute_allowlisted_paths() {
    for name in ["sh", "tar"] {
        if let Ok(path) = resolve(name) {
            assert!(path.is_absolute());
            assert_eq!(path.file_name().and_then(|part| part.to_str()), Some(name));
            if option_env!("STRATA_TRUSTED_COMMAND_PATH").is_none() {
                assert!(
                    SEARCH_ROOTS.iter().any(|root| path.starts_with(root)),
                    "{name} resolved to {}",
                    path.display()
                );
            }
            let canonical = path.canonicalize().expect("canonical helper");
            assert!(
                TRUST_ROOTS.iter().any(|root| {
                    let root = Path::new(root);
                    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
                    canonical.starts_with(root)
                }),
                "{name} canonical {} not under a trust root",
                canonical.display()
            );
            let program = command(name).expect("command").get_program().to_owned();
            assert_eq!(program, path.as_os_str());
        }
    }
    assert!(command("strata-missing-trusted-helper").is_err());
}
