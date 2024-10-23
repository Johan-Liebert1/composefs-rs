use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};

use composefs_experiments::{
    oci,
    repository::Repository,
    util::parse_sha256,
};


/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group="repopath")]
    repo: Option<PathBuf>,
    #[clap(long, group="repopath")]
    user: bool,
    #[clap(long, group="repopath")]
    system: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar file as a splitstream in the repository.
    ImportLayer {
        sha256: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream
        name: String,
    },
    CreateDumpfile {
        layers: Vec<String>,
    },
    Pull {
        image: String,
        name: Option<String>,
    },
    CreateImage {
        name: String,
        layers: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a sha256 digest or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC,
    /// Imports a composefs image (unsafe!)
    ImportImage {
        reference: String,
    },
    /// Commands for dealing with OCI layers
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either a sha256 digest or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
}

fn main() -> Result<()> {
    let args = App::parse();

    let repo = (
        if let Some(path) = args.repo {
            Repository::open_path(path)
        } else if args.system {
            Repository::open_system()
        } else if args.user {
            Repository::open_user()
        } else if rustix::process::getuid().is_root() {
            Repository::open_system()
        } else {
            Repository::open_user()
        }
    )?;

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        },
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, &mut std::io::stdout())?;
        },
        Command::ImportImage { reference, } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", hex::encode(image_id));
        },
        Command::Oci{ cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, sha256 } => {
                let object_id = oci::import_layer(&repo, &parse_sha256(sha256)?, name.as_deref(), &mut std::io::stdin())?;
                println!("{}", hex::encode(object_id));
            },
            OciCommand::LsLayer { name } => {
                oci::ls_layer(&repo, &name)?;
            },
            OciCommand::CreateDumpfile { layers } => {
                oci::image::create_dumpfile(&repo, &layers)?;
            },
            OciCommand::CreateImage { name, layers } => {
                let image_id = oci::image::create_image(&repo, &name, &layers)?;
                println!("{}", hex::encode(image_id));
            },
            OciCommand::Pull { ref image, name } => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to build tokio runtime");
                // And invoke the async_main
                runtime.block_on(async move { oci::pull(&repo, image, name.as_deref()).await })?;
            }
        }
        Command::Mount { name, mountpoint } => {
            repo.mount(&name, &mountpoint)?;
        },
        Command::GC => {
            repo.gc()?;
        }
    }
    Ok(())
}
