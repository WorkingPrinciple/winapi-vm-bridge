use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wvb_receipt::{RuntimeReceipt, public_key};
use zeroize::Zeroize;

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::Sign {
            input,
            output,
            public_key: public_key_path,
        } => {
            let mut seed = [0_u8; 32];
            io::stdin().read_exact(&mut seed)?;
            let mut receipt: RuntimeReceipt = serde_json::from_slice(&fs::read(input)?)?;
            receipt.sign(&seed)?;
            let key = public_key(&seed)?;
            seed.zeroize();
            fs::write(output, receipt.canonical_bytes()?)?;
            fs::write(public_key_path, key)?;
            println!("runtime-receipt=authenticated");
        }
        Command::Verify { input, public_key } => {
            let receipt: RuntimeReceipt = serde_json::from_slice(&fs::read(input)?)?;
            receipt.verify(&fs::read(public_key)?)?;
            println!("runtime-receipt=verified");
        }
    }
    Ok(())
}
