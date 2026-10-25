//! Local, operator-pinned WX-07 execution; not arbitrary remote process execution.

use super::{ActorConfig, Result, bounded_read, now_ms, registry, validate_bounds};
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use wvb_authz::{ActorId, Registry, Role};
use wvb_broker::{BrokerError, CallHandler};
use wvb_call::{CallRequest, CallResult};
use wvb_integrity::{canonical_root, resolve_regular_file, sha256_bytes};

#[cfg(any(windows, test))]
const SCRIPT: &str = include_str!("../../../../../setup/windows-vm/run-package-observer.ps1");
const OPERATION: u32 = 1;
const SCHEMA: u32 = 1;

#[cfg(any(windows, test))]
fn launcher_command(stage: &Path) -> Result<String> {
    let stage = stage.to_str().ok_or("run directory is not valid Unicode")?;
    Ok(format!(
        "& {{ {SCRIPT} }} -Stage '{}'",
        stage.replace('\'', "''")
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub listen: std::net::SocketAddr,
    pub private_key_path: PathBuf,
    pub actors: Vec<ActorConfig>,
    pub plan_path: PathBuf,
    pub plan_sha256: [u8; 32],
    pub run_root: PathBuf,
    pub lifetime_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    observer: String,
    observer_sha256: String,
    contract_sha256: String,
    shapes_sha256: String,
    module_sha256: String,
    context: String,
    package_family_name: String,
    app_id: String,
    timeout_ms: u64,
    max_output_bytes: usize,
}

fn hash_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(any(windows, test))]
fn os_build(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    (3..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u32>().is_ok())
}

fn hex(bytes: &[u8]) -> String {
    let digits = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(digits[usize::from(byte >> 4)]));
        result.push(char::from(digits[usize::from(byte & 15)]));
    }
    result
}

impl Plan {
    fn validate(&self) -> Result<()> {
        wvb_integrity::validate_portable_relative_path(&self.observer)?;
        if !Path::new(&self.observer)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            || ![
                &self.observer_sha256,
                &self.contract_sha256,
                &self.shapes_sha256,
                &self.module_sha256,
            ]
            .iter()
            .all(|value| hash_string(value))
            || ![&self.context, &self.package_family_name, &self.app_id]
                .iter()
                .all(|value| name(value))
            || self.context == "unpackaged"
            || self.max_output_bytes > 1_048_576
        {
            return Err("invalid package observer plan".into());
        }
        validate_bounds(self.max_output_bytes, self.timeout_ms)
    }

    fn verify_observer(&self, root: &Path) -> Result<Vec<u8>> {
        let path = resolve_regular_file(root, &self.observer)?;
        let bytes = bounded_read(&path, 64 * 1_048_576)?;
        if hex(&sha256_bytes(&bytes)) != self.observer_sha256 {
            return Err("observer SHA256 mismatch".into());
        }
        Ok(bytes)
    }
}

// This is the sole adapter for WX-07's per-context observation proof fields.
#[cfg(any(windows, test))]
fn validate_output(plan: &Plan, bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > plan.max_output_bytes {
        return Err("missing or oversized observer output".into());
    }
    let output: Value = serde_json::from_slice(bytes)?;
    if output["schema"] != "whiny.observations.v1" {
        return Err("observer refused or returned an unsupported schema".into());
    }
    let observed = output["observed_on"]
        .as_object()
        .ok_or("missing observer identity proof")?;
    let get = |key: &str| observed.get(key).and_then(Value::as_str);
    let context = |key: &str| get(&format!("{}.{key}", plan.context));
    if get("observer_mode") != Some("native")
        || get("observer_sha256") != Some(&plan.observer_sha256)
        || get("module_sha256") != Some(&plan.module_sha256)
        || get("contract_sha256") != Some(&plan.contract_sha256)
        || get("shapes_sha256") != Some(&plan.shapes_sha256)
        || get("os_build").is_none_or(|value| !os_build(value))
        || context("module_path").is_none_or(str::is_empty)
        || context("session_id") != Some("1")
        || context("package_identity") != Some("GetCurrentPackageFamilyName=0")
        || context("package_family_name")
            .is_none_or(|family| !family.eq_ignore_ascii_case(&plan.package_family_name))
    {
        return Err("observer session/package/artifact proof mismatch".into());
    }
    let cells = output["cells"]
        .as_array()
        .ok_or("missing observation cells")?;
    if cells.is_empty()
        || cells
            .iter()
            .any(|cell| cell["context"].as_str() != Some(&plan.context))
    {
        return Err("empty or mixed-context observation cells".into());
    }
    Ok(json!({
        "session_id": 1,
        "package_family_name": context("package_family_name"),
        "package_identity": "GetCurrentPackageFamilyName=0",
        "os_build": get("os_build"),
        "module_path": context("module_path"),
        "module_sha256": plan.module_sha256,
    }))
}

pub(super) struct Observer {
    plan: Plan,
    root: PathBuf,
    run_root: PathBuf,
    hash: [u8; 32],
    actor: ActorId,
    registry: Arc<RwLock<Registry>>,
    used: AtomicBool,
}

impl Observer {
    fn authorize(&self, request: &CallRequest) -> Result<()> {
        if request.adapter_hash != self.hash
            || request.operation_id != OPERATION
            || request.request_schema_id != SCHEMA
            || !request.body.is_empty()
            || request.idempotency_key.is_some()
            || request.deduplication_mode != 0
        {
            return Err(
                "observer requires exact operation/schema 1 and empty request; no replay".into(),
            );
        }
        self.registry
            .read()
            .map_err(|_| "authorization registry poisoned")?
            .authorize_role_exact(
                self.actor,
                Role::PackageObserver,
                self.hash,
                Some(OPERATION),
                now_ms()?,
            )
            .map_err(|error| format!("package observer grant: {error:?}"))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl CallHandler for Observer {
    async fn handle_call(
        &self,
        request: CallRequest,
    ) -> std::result::Result<CallResult, BrokerError> {
        let failure = |error: Box<dyn std::error::Error>| BrokerError::Handler(error.to_string());
        self.authorize(&request).map_err(failure)?;
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(BrokerError::Handler(
                "observer capability already consumed; no retry".into(),
            ));
        }
        let observer = self.plan.verify_observer(&self.root).map_err(failure)?;
        let plan = self.plan.clone();
        let root = self.run_root.clone();
        let result = tokio::task::spawn_blocking(move || {
            execute(&plan, &observer, &root).map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| BrokerError::Handler(error.to_string()))?
        .map_err(BrokerError::Handler)?;
        Ok(CallResult {
            response_schema_id: SCHEMA,
            operation_uuid: None,
            native_status: 0_i32.to_le_bytes().to_vec(),
            body: result,
        })
    }
}

#[cfg(not(windows))]
fn execute(_plan: &Plan, _observer: &[u8], _root: &Path) -> Result<Vec<u8>> {
    Err("package observer execution requires Windows; no task was started".into())
}

#[cfg(windows)]
fn execute(plan: &Plan, observer: &[u8], root: &Path) -> Result<Vec<u8>> {
    use ring::rand::{SecureRandom, SystemRandom};
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let root = canonical_root(root)?;
    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "run nonce generation failed")?;
    let stage = root.join(format!("wvb-observer-{}", hex(&nonce)));
    std::fs::create_dir(&stage)?;
    let write_new = |name: &str, bytes: &[u8]| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    };
    write_new("observer.exe", observer)?;
    write_new("plan.json", &serde_json::to_vec(plan)?)?;
    write_new("runner.ps1", SCRIPT.as_bytes())?;
    eprintln!(
        "wvb: observer run {}; retain on error; no automatic replay",
        stage.display()
    );
    let system_root = std::env::var_os("SystemRoot").ok_or("missing SystemRoot")?;
    let powershell =
        PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let diagnostics = stage.join("launcher.stderr");
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&diagnostics)?;
    let mut child = Command::new(powershell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(launcher_command(&stage)?)
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_millis(plan.timeout_ms + 8000);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|error| {
                format!(
                    "launcher termination failed: {error}; reconcile {}",
                    stage.display()
                )
            })?;
            child.wait()?;
            return Err(format!("launcher deadline expired; reconcile task/run {}; observer completion/quiescence unknown; no replay", stage.display()).into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if !status.success() {
        let stderr = bounded_read(&diagnostics, 16_384)?;
        return Err(format!(
            "observer task failed; run {}; completion/quiescence may be unknown; no replay: {}",
            stage.display(),
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    let path = resolve_regular_file(&canonical_root(&stage.join("output"))?, "observations.json")?;
    let bytes = bounded_read(&path, plan.max_output_bytes)?;
    encode_result(plan, &bytes, &stage)
}

#[cfg(any(windows, test))]
fn encode_result(plan: &Plan, bytes: &[u8], stage: &Path) -> Result<Vec<u8>> {
    let proof = validate_output(plan, bytes)?;
    Ok(serde_json::to_vec(&json!({
        "output_sha256": hex(&sha256_bytes(bytes)),
        "output_bytes": bytes.len(),
        "observations_utf8": std::str::from_utf8(bytes)?,
        "observer_sha256": plan.observer_sha256,
        "context": plan.context,
        "app_id": plan.app_id,
        "proof": proof,
        "run_directory": stage,
        "task_completed": true,
        "task_retained": true,
        "observer_process_quiescence": "not-attested",
    }))?)
}

pub(super) async fn serve(config: Config) -> Result<()> {
    validate_bounds(1, config.lifetime_ms)?;
    let plan_bytes = bounded_read(&config.plan_path, super::CONFIG_MAX)?;
    if sha256_bytes(&plan_bytes) != config.plan_sha256 {
        return Err("package observer plan SHA256 mismatch".into());
    }
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    plan.validate()?;
    // Budget includes JSON string escaping of the exact original bytes plus proof.
    let capacity = plan
        .max_output_bytes
        .checked_mul(6)
        .ok_or("output bound overflow")?
        + 8192;
    if capacity > wvb_call::LOGICAL_MAX || plan.timeout_ms + 10_000 > config.lifetime_ms {
        return Err("observer result or time budget exceeds server bounds".into());
    }
    let root = canonical_root(config.plan_path.parent().ok_or("plan has no parent")?)?;
    plan.verify_observer(&root)?;
    let run_root = canonical_root(&config.run_root)?;
    let registry = Arc::new(RwLock::new(registry(&config.actors)?));
    super::serve_authenticated(
        config.listen,
        &config.private_key_path,
        config.lifetime_ms,
        registry.clone(),
        move |actor, _nonce| {
            Ok((
                Arc::new(Observer {
                    plan,
                    root,
                    run_root,
                    hash: config.plan_sha256,
                    actor,
                    registry,
                    used: AtomicBool::new(false),
                }) as Arc<dyn CallHandler>,
                None,
            ))
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wvb_authz::Grant;

    fn plan() -> Plan {
        Plan {
            observer: "observer.exe".into(),
            observer_sha256: hex(&sha256_bytes(b"observer")),
            contract_sha256: "a".repeat(64),
            shapes_sha256: "b".repeat(64),
            module_sha256: "c".repeat(64),
            context: "packaged-gamingapp-signed".into(),
            package_family_name: "Microsoft.GamingApp_8wekyb3d8bbwe".into(),
            app_id: "Microsoft.Xbox.App".into(),
            timeout_ms: 5000,
            max_output_bytes: 4096,
        }
    }

    fn output(plan: &Plan) -> Value {
        let mut observed = json!({
            "observer_mode": "native", "observer_sha256": plan.observer_sha256,
            "module_sha256": plan.module_sha256, "contract_sha256": plan.contract_sha256,
            "shapes_sha256": plan.shapes_sha256, "os_build": "10.0.26300",
        });
        for (key, value) in [
            ("session_id", "1"),
            ("package_identity", "GetCurrentPackageFamilyName=0"),
            ("package_family_name", &plan.package_family_name),
            ("module_path", "C:\\Windows\\System32\\ntdll.dll"),
        ] {
            observed[format!("{}.{key}", plan.context)] = json!(value);
        }
        json!({"schema":"whiny.observations.v1", "observed_on":observed,
            "cells":[{"id":"site-b.packaged-gamingapp-signed", "context":plan.context,
                "when":{"TokenHandle":"0xfffffffffffffffa"}, "result":"0x0", "effects":{}}]})
    }

    fn request() -> CallRequest {
        CallRequest {
            adapter_hash: [3; 32],
            operation_id: 1,
            request_schema_id: 1,
            deduplication_mode: 0,
            idempotency_key: None,
            disconnect_policy: 0,
            sensitivity: 0,
            body: Vec::new(),
        }
    }

    fn observer(root: &Path) -> Observer {
        let mut registry = Registry::default();
        registry.register([1; 16], [2; 32]).unwrap();
        Observer {
            plan: plan(),
            root: root.into(),
            run_root: root.into(),
            hash: [3; 32],
            actor: [1; 16],
            registry: Arc::new(RwLock::new(registry)),
            used: AtomicBool::new(false),
        }
    }

    fn grant(
        observer: &Observer,
        role: Role,
        hash: Option<[u8; 32]>,
        operation: Option<u32>,
        expiry: Option<u64>,
    ) {
        observer
            .registry
            .write()
            .unwrap()
            .grant(
                [1; 16],
                Grant {
                    role,
                    adapter_hash: hash,
                    operation_id: operation,
                    expires_at_unix_ms: expiry,
                },
            )
            .unwrap();
    }

    #[test]
    fn proof_rejects_session_zero_wrong_package_missing_identity_and_changed_pins() {
        let plan = plan();
        let valid = output(&plan);
        let mut bytes = serde_json::to_vec_pretty(&valid).unwrap();
        bytes.extend_from_slice(b"\r\n");
        assert!(validate_output(&plan, &bytes).is_ok());
        let result: Value =
            serde_json::from_slice(&encode_result(&plan, &bytes, Path::new("run")).unwrap())
                .unwrap();
        assert_eq!(result["output_sha256"], hex(&sha256_bytes(&bytes)));
        assert_eq!(result["output_bytes"], bytes.len());
        assert_eq!(
            result["observations_utf8"].as_str().unwrap().as_bytes(),
            bytes
        );
        assert_eq!(result["proof"]["session_id"], 1);
        assert_eq!(result["observer_process_quiescence"], "not-attested");
        for (key, value) in [
            ("session_id", "0"),
            ("session_id", "2"),
            ("package_family_name", "Other_Family"),
            ("package_identity", "GetCurrentPackageFamilyName=15700"),
        ] {
            let mut changed = valid.clone();
            changed["observed_on"][format!("{}.{key}", plan.context)] = json!(value);
            assert!(
                validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "{key}: {value}"
            );
        }
        for key in [
            "observer_mode",
            "observer_sha256",
            "module_sha256",
            "contract_sha256",
            "shapes_sha256",
            "os_build",
        ] {
            let mut changed = valid.clone();
            changed["observed_on"][key] = json!("wrong");
            assert!(
                validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "{key}"
            );
            changed["observed_on"].as_object_mut().unwrap().remove(key);
            assert!(
                validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "missing {key}"
            );
        }
        for key in [
            "module_path",
            "session_id",
            "package_identity",
            "package_family_name",
        ] {
            let mut changed = valid.clone();
            changed["observed_on"]
                .as_object_mut()
                .unwrap()
                .remove(&format!("{}.{key}", plan.context));
            assert!(validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut changed = valid.clone();
        changed["cells"][0]["context"] = json!("unpackaged");
        assert!(validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err());
        changed["cells"] = json!([]);
        assert!(validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err());
        changed["schema"] = json!("whiny.observer-refusal.v1");
        assert!(validate_output(&plan, &serde_json::to_vec(&changed).unwrap()).is_err());
        assert!(validate_output(&plan, b"not JSON").is_err());
        assert!(validate_output(&plan, &vec![b' '; plan.max_output_bytes + 1]).is_err());
    }

    #[test]
    fn capability_is_independent_exact_expiring_and_revocable() {
        for (role, hash, operation, expiry) in [
            (Role::Invoke, Some([3; 32]), Some(1), None),
            (Role::Operator, Some([3; 32]), Some(1), None),
            (Role::PackageObserver, None, Some(1), None),
            (Role::PackageObserver, Some([3; 32]), None, None),
            (Role::PackageObserver, Some([4; 32]), Some(1), None),
            (Role::PackageObserver, Some([3; 32]), Some(2), None),
            (Role::PackageObserver, Some([3; 32]), Some(1), Some(0)),
        ] {
            let observer = observer(Path::new("."));
            grant(&observer, role, hash, operation, expiry);
            assert!(observer.authorize(&request()).is_err());
            assert!(!observer.used.load(Ordering::SeqCst));
        }
        let observer = observer(Path::new("."));
        grant(
            &observer,
            Role::PackageObserver,
            Some([3; 32]),
            Some(1),
            None,
        );
        assert!(observer.authorize(&request()).is_ok());
        let mut changed = request();
        changed.body.push(1);
        assert!(observer.authorize(&changed).is_err());
        changed = request();
        changed.adapter_hash = [4; 32];
        assert!(observer.authorize(&changed).is_err());
        changed = request();
        changed.operation_id = 2;
        assert!(observer.authorize(&changed).is_err());
        changed = request();
        changed.request_schema_id = 2;
        assert!(observer.authorize(&changed).is_err());
        changed = request();
        changed.idempotency_key = Some([1; 16]);
        assert!(observer.authorize(&changed).is_err());
        changed = request();
        changed.deduplication_mode = 1;
        assert!(observer.authorize(&changed).is_err());
        observer.registry.write().unwrap().revoke([1; 16]).unwrap();
        assert!(observer.authorize(&request()).is_err());
        assert_eq!(Role::try_from(7).unwrap(), Role::PackageObserver);
    }

    #[tokio::test]
    async fn changed_observer_consumes_once_without_launch_or_replay() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("observer.exe"), b"changed").unwrap();
        let observer = observer(&canonical_root(dir.path()).unwrap());
        grant(
            &observer,
            Role::PackageObserver,
            Some([3; 32]),
            Some(1),
            None,
        );
        let error = observer
            .handle_call(request())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("SHA256 mismatch"), "{error}");
        let error = observer
            .handle_call(request())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("already consumed"));
    }

    #[test]
    fn plan_paths_names_hashes_and_bounds_fail_closed() {
        let valid = plan();
        valid.validate().unwrap();
        for path in [
            "../observer.exe",
            "/observer.exe",
            "C:/observer.exe",
            "observer.dll",
            "bad name.exe",
        ] {
            let mut changed = valid.clone();
            changed.observer = path.into();
            assert!(changed.validate().is_err());
        }
        for name in ["", "x';Start-Process calc", "x\"y", "x\\y", "x y"] {
            let mut changed = valid.clone();
            changed.context = name.into();
            assert!(changed.validate().is_err());
            changed = valid.clone();
            changed.app_id = name.into();
            assert!(changed.validate().is_err());
            changed = valid.clone();
            changed.package_family_name = name.into();
            assert!(changed.validate().is_err());
        }
        let mut changed = valid.clone();
        changed.observer_sha256 = "A".repeat(64);
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.context = "unpackaged".into();
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.max_output_bytes = 0;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.max_output_bytes = 1_048_577;
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.timeout_ms = 600_001;
        assert!(changed.validate().is_err());
        let mut json = serde_json::to_value(&valid).unwrap();
        json["command"] = json!("arbitrary");
        assert!(serde_json::from_value::<Plan>(json).is_err());
    }

    #[test]
    fn task_boundary_has_interactive_session_checks_and_exact_wx07_arguments() {
        assert!(SCRIPT.contains("-LogonType Interactive -RunLevel Limited"));
        assert!(SCRIPT.contains("SessionId -ne 1"));
        assert!(SCRIPT.contains("WTSQuerySessionInformationW"));
        assert!(SCRIPT.contains("Get-SessionOneSid"));
        assert!(SCRIPT.contains("Invoke-CommandInDesktopPackage -PackageFamilyName"));
        assert!(SCRIPT.contains("-AppId $plan.app_id"));
        assert!(SCRIPT.contains("--context "));
        assert!(SCRIPT.contains(" --out "));
        assert!(!SCRIPT.contains("-Password"));
        assert!(!SCRIPT.contains("Stop-ScheduledTask"));
        assert!(!SCRIPT.contains("Unregister-ScheduledTask"));
        assert!(!SCRIPT.contains("Register-ScheduledTask -Force"));
        assert!(
            launcher_command(Path::new("C:\\operator's runs\\run"))
                .unwrap()
                .ends_with("-Stage 'C:\\operator''s runs\\run'")
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn both_invoke_and_capability_are_required_before_host_platform_refusal() {
        use wvb_broker::AuthorizedCallHandler;

        for capability in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("observer.exe"), b"observer").unwrap();
            let observer = Arc::new(observer(&canonical_root(dir.path()).unwrap()));
            if capability {
                grant(
                    &observer,
                    Role::PackageObserver,
                    Some([3; 32]),
                    Some(1),
                    None,
                );
            } else {
                grant(&observer, Role::Invoke, Some([3; 32]), Some(1), None);
            }
            let authorized =
                AuthorizedCallHandler::new([1; 16], observer.registry.clone(), observer.clone());
            assert!(authorized.handle_call(request()).await.is_err());
            assert!(!observer.used.load(Ordering::SeqCst));
            grant(
                &observer,
                if capability {
                    Role::Invoke
                } else {
                    Role::PackageObserver
                },
                Some([3; 32]),
                Some(1),
                None,
            );
            let error = authorized
                .handle_call(request())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("requires Windows"), "{error}");
            assert!(observer.used.load(Ordering::SeqCst));
            let error = authorized
                .handle_call(request())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("already consumed"), "{error}");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
