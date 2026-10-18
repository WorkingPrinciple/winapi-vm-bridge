use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wvb_package::{PackageManager, PackageManifest};

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    Stage {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    Activate {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        health_receipt: PathBuf,
    },
    Rollback {
        #[arg(long)]
        root: PathBuf,
    },
    UninstallPreflight {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        version: String,
    },
    Uninstall {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        version: String,
    },
}

fn manifest(path: &PathBuf) -> Result<PackageManifest, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::Verify {
            source,
            manifest: path,
        } => {
            manifest(&path)?.verify_source(&source)?;
            println!("package-verify=ok");
        }
        Command::Stage {
            root,
            source,
            manifest: path,
        } => {
            let manager = PackageManager::open(&root)?;
            let staged = manager.stage(&source, &manifest(&path)?)?;
            println!("package-stage=ok path={}", staged.display());
        }
        Command::Activate {
            root,
            manifest: path,
            health_receipt,
        } => {
            let manager = PackageManager::open(&root)?;
            let health = fs::read_to_string(&health_receipt)?;
            let value = manifest(&path)?;
            let slot = manager.activate(&value, |_| health.trim() == "PASS")?;
            println!("package-activate=ok version={}", slot.package_version);
        }
        Command::Rollback { root } => {
            let slot = PackageManager::open(&root)?.rollback()?;
            println!("package-rollback=ok version={}", slot.package_version);
        }
        Command::UninstallPreflight { root, version } => {
            let paths = PackageManager::open(&root)?.uninstall_preflight(&version)?;
            for path in paths {
                println!("{}", path.display());
            }
        }
        Command::Uninstall { root, version } => {
            PackageManager::open(&root)?.uninstall(&version)?;
            println!("package-uninstall=ok version={version}");
        }
    }
    Ok(())
}
