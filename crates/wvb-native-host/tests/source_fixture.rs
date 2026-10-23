#![cfg(all(feature = "source-fixture", target_os = "macos"))]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use wvb_broker::TypedDispatchModule;
use wvb_call::LOGICAL_MAX;
use wvb_integrity::sha256_file;
use wvb_native_host::{NativeHostConfig, NativeHostError, source_fixture::SourceFixtureDispatcher};

fn build(directory: &Path, missing_export: bool) -> PathBuf {
    let path = directory.join(if missing_export {
        "missing.dylib"
    } else {
        "dispatch.dylib"
    });
    let mut command = Command::new("clang");
    command.args(["-dynamiclib", "-std=c17", "-Wall", "-Wextra", "-Werror"]);
    if missing_export {
        command.arg("-DNO_DISPATCH");
    }
    let output = command
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source_dispatch.c"))
        .arg("-o")
        .arg(&path)
        .output()
        .expect("source fixture compiler");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

#[test]
fn source_fixture_checks_hash_export_lifetime_and_single_invocation() {
    let directory = std::env::temp_dir().join(format!(
        "wvb-source-fixture-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = build(&directory, false);
    let missing = build(&directory, true);
    let mut config = NativeHostConfig {
        dispatcher_path: path.clone(),
        dispatcher_sha256: [0; 32],
        response_capacity: LOGICAL_MAX,
    };
    assert!(matches!(
        unsafe { SourceFixtureDispatcher::load(&config) },
        Err(NativeHostError::LoadFailed)
    ));
    config.dispatcher_sha256 = sha256_file(&path).unwrap();
    let dispatcher = unsafe { SourceFixtureDispatcher::load(&config) }.unwrap();
    drop(config);
    let first = dispatcher.dispatch(1, &[1; 8]);
    assert_eq!(first.status, 0);
    assert_eq!(first.body, 1_u32.to_ne_bytes());
    let oversized = dispatcher.dispatch(1, &vec![0; LOGICAL_MAX + 1]);
    assert_eq!(oversized.status, -1);
    assert!(oversized.body.is_empty());
    let failed = dispatcher.dispatch(2, &[]);
    assert_eq!(failed.status, -17);
    assert_eq!(failed.body, 2_u32.to_ne_bytes());
    let invalid = dispatcher.dispatch(3, &[]);
    assert_eq!(invalid.status, -1);
    assert!(invalid.body.is_empty());
    drop(dispatcher);
    assert!(matches!(
        unsafe {
            SourceFixtureDispatcher::load(&NativeHostConfig {
                dispatcher_sha256: sha256_file(&missing).unwrap(),
                dispatcher_path: missing.clone(),
                response_capacity: LOGICAL_MAX,
            })
        },
        Err(NativeHostError::ExportMissing)
    ));
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(missing).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
