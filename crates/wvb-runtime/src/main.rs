use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde_json::json;
use wvb_operations::{CheckStatus, OverallStatus, ReadinessCheck, ReadinessRegistry};
use wvb_owner::{AttemptCorrelation, TerminalReceiptInput};
use wvb_package::{HealthReceipt, PackageManifest};
use wvb_state::{ActorRecord, OperationStatus, Store};
use zeroize::Zeroize;

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
    BeginAttempt {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        correlation: PathBuf,
        #[arg(long)]
        actor_id: String,
        #[arg(long)]
        actor_public_key: String,
        #[arg(long)]
        trace_id: String,
        #[arg(long)]
        now_unix_ms: u64,
    },
    CompleteReceipt {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        correlation: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
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
        Command::BeginAttempt {
            state,
            correlation,
            actor_id,
            actor_public_key,
            trace_id,
            now_unix_ms,
        } => {
            let mut store = Store::open(&state)?;
            let correlation: AttemptCorrelation = serde_json::from_slice(&fs::read(correlation)?)?;
            let actor_id = parse_hex(&actor_id)?;
            if !store
                .actors()?
                .iter()
                .any(|actor| actor.actor_id == actor_id)
            {
                store.commit_pairing(
                    &ActorRecord {
                        actor_id,
                        public_key: parse_hex(&actor_public_key)?,
                        label: String::from("runtime-owner-acceptance"),
                        active: true,
                    },
                    &[],
                    b"runtime owner acceptance actor",
                )?;
            }
            let mut operation =
                correlation.operation_record(actor_id, now_unix_ms, parse_hex(&trace_id)?)?;
            store.create_operation(&operation, b"runtime owner attempt created")?;
            operation.status = OperationStatus::Running;
            operation.stage = operation.stage.saturating_add(1);
            operation.updated_unix_ms = now_unix_ms;
            operation.started_unix_ms = Some(now_unix_ms);
            store.transition_operation(
                OperationStatus::Queued,
                &operation,
                b"runtime owner attempt running",
            )?;
            println!("runtime-attempt=running actor={}", hex(&actor_id));
            Ok(())
        }
        Command::CompleteReceipt {
            state,
            correlation,
            input,
            output,
            public_key,
        } => {
            let mut store = Store::open(&state)?;
            let mut correlation: AttemptCorrelation =
                serde_json::from_slice(&fs::read(correlation)?)?;
            let input: TerminalReceiptInput = serde_json::from_slice(&fs::read(input)?)?;
            let mut seed = [0_u8; 32];
            io::stdin().read_exact(&mut seed)?;
            let emitted = correlation.complete_with_receipt(&mut store, seed, input);
            seed.zeroize();
            let emitted = emitted?;
            fs::write(output, emitted.receipt.canonical_bytes()?)?;
            fs::write(public_key, emitted.public_key)?;
            println!(
                "runtime-receipt=committed attempt={}",
                correlation
                    .attempt_id
                    .iter()
                    .fold(String::new(), |mut value, byte| {
                        use std::fmt::Write;
                        write!(value, "{byte:02x}").expect("writing to String cannot fail");
                        value
                    })
            );
            Ok(())
        }
    }
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    if value.len() != N * 2 {
        return Err("hex value has invalid length".into());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
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
