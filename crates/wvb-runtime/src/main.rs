use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde_json::json;
use wvb_operations::{CheckStatus, OverallStatus, ReadinessCheck, ReadinessRegistry};
use wvb_package::{HealthReceipt, PackageManifest};
use wvb_state::Store;

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    InitState {
        #[arg(long)]
        state: PathBuf,
    },
    Doctor {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        package_root: PathBuf,
        #[arg(long)]
        receipt: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::InitState { state } => {
            if let Some(parent) = state.parent() {
                fs::create_dir_all(parent)?;
            }
            Store::open(&state)?;
            println!("runtime-state=initialized path={}", state.display());
            Ok(())
        }
        Command::Doctor {
            state,
            package_root,
            receipt,
        } => doctor(&state, &package_root, receipt),
    }
}

fn doctor(
    state: &Path,
    package_root: &Path,
    receipt: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut readiness = ReadinessRegistry::new(
        env!("CARGO_PKG_VERSION").to_owned(),
        [
            String::from("runtime-self"),
            String::from("state-chain"),
            String::from("package-manifest"),
        ],
    )?;
    readiness.update(ReadinessCheck {
        code: String::from("runtime-self"),
        status: CheckStatus::Ready,
        observed_unix_ms: now_ms(),
        measurement: None,
    })?;
    let state_status = Store::open_read_only(state)
        .and_then(|store| store.verify_chain())
        .map_or(CheckStatus::Blocked, |_| CheckStatus::Ready);
    readiness.update(ReadinessCheck {
        code: String::from("state-chain"),
        status: state_status,
        observed_unix_ms: now_ms(),
        measurement: None,
    })?;
    let manifest_path = package_root.join("manifest.jcs");
    let manifest = fs::read(&manifest_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<PackageManifest>(&bytes).ok());
    let package_ready = manifest
        .as_ref()
        .is_some_and(|manifest| manifest.verify_source(package_root).is_ok());
    readiness.update(ReadinessCheck {
        code: String::from("package-manifest"),
        status: if package_ready {
            CheckStatus::Ready
        } else {
            CheckStatus::Blocked
        },
        observed_unix_ms: now_ms(),
        measurement: None,
    })?;
    let snapshot = readiness.snapshot(now_ms());
    println!(
        "{}",
        serde_json::to_string(&json!({
            "sourceVersion": snapshot.source_version,
            "generatedUnixMs": snapshot.generated_unix_ms,
            "overall": format!("{:?}", snapshot.overall).to_ascii_lowercase(),
            "checks": snapshot.checks.iter().map(|check| json!({
                "code": check.code,
                "status": format!("{:?}", check.status).to_ascii_lowercase(),
                "observedUnixMs": check.observed_unix_ms,
                "measurement": check.measurement,
            })).collect::<Vec<_>>(),
        }))?
    );
    if snapshot.overall != OverallStatus::Ready {
        return Err("runtime doctor is not ready".into());
    }
    if let Some(path) = receipt {
        let manifest = manifest.ok_or("runtime package manifest is unavailable")?;
        let health = HealthReceipt {
            status: String::from("PASS"),
            package_version: manifest.package_version.clone(),
            manifest_sha256: manifest.sha256()?,
            package_root: fs::canonicalize(package_root)?
                .to_string_lossy()
                .into_owned(),
        };
        fs::write(path, serde_json::to_vec(&health)?)?;
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
