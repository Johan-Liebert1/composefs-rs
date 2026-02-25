//! The create

use cfsctl::{App, HashType, open_repo, run_cmd_with_repo};

use anyhow::Result;
use clap::Parser;
use composefs::fsverity::{Sha256HashValue, Sha512HashValue};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}
