pub mod image;
pub mod tar;

use std::{collections::HashMap, io::Read, iter::zip, marker::PhantomData, path::Path, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use containers_image_proxy::{ImageProxy, ImageProxyConfig, OpenedImage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;

use crate::{
    fs::write_to_path,
    fsverity::Sha256HashValue,
    oci::tar::{get_entry, split_async},
    repository::Repository,
    splitstream::DigestMap,
    util::parse_sha256,
};

pub fn import_layer(
    repo: &Repository,
    sha256: &Sha256HashValue,
    name: Option<&str>,
    tar_stream: &mut impl Read,
) -> Result<Sha256HashValue> {
    repo.ensure_stream(sha256, |writer| tar::split(tar_stream, writer), name)
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    let mut split_stream = repo.open_stream(name, None)?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{}", entry);
    }

    Ok(())
}

struct ImageOp<'repo: 'static> {
    repo: Arc<Repository>,
    proxy: Arc<ImageProxy>,
    img: OpenedImage,
    progress: MultiProgress,
    _x: PhantomData<&'repo ()>,
}

fn sha256_from_descriptor(descriptor: &Descriptor) -> Result<Sha256HashValue> {
    let Some(digest) = descriptor.as_digest_sha256() else {
        bail!("Descriptor in oci config is not sha256");
    };
    parse_sha256(digest)
}

fn sha256_from_digest(digest: &str) -> Result<Sha256HashValue> {
    match digest.strip_prefix("sha256:") {
        Some(rest) => parse_sha256(rest),
        None => bail!("Manifest has non-sha256 digest"),
    }
}

type ContentAndVerity = (Sha256HashValue, Sha256HashValue);

// fn foo<T: Send>(x: T) {}
//
// fn bar(i: ImageOp) {
//     foo(i);
// }

impl<'repo> ImageOp<'repo> {
    async fn new(repo: Arc<Repository>, imgref: &str) -> Result<Self> {
        let config = ImageProxyConfig {
            // auth_anonymous: true, debug: true, insecure_skip_tls_verification: Some(true),
            ..ImageProxyConfig::default()
        };
        let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;
        let proxy = Arc::new(proxy);
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        let progress = MultiProgress::new();
        Ok(ImageOp {
            repo,
            proxy,
            img,
            progress,
            _x: PhantomData::default(),
        })
    }

    pub async fn ensure_layer(
        &self,
        layer_sha256: &Sha256HashValue,
        descriptor: &Descriptor,
        join_set: &mut JoinSet<Result<[u8; 32], anyhow::Error>>,
    ) -> Result<()> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.
        //

        if let Some(layer_id) = self.repo.check_stream(layer_sha256)? {
            self.progress
                .println(format!("Already have layer {}", hex::encode(layer_sha256)))?;
            Ok(())
        } else {
            // Otherwise, we need to fetch it...
            //
            // self.proxy is not Send because driver is not Send

            let (blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;

            let repo = Arc::clone(&self.repo);
            let self_progress = self.progress.clone(); // TODO: .clone()
            let descriptor_size = descriptor.size();
            let layer_sha256 = *layer_sha256;

            join_set.spawn(
                async move {
                    let bar = self_progress.add(ProgressBar::new(descriptor_size));
                    bar.set_style(ProgressStyle::with_template("[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}")
                    .unwrap()
                    .progress_chars("##-"));

                    let progress = bar.wrap_async_read(blob_reader);
                    self_progress
                        .println(format!("Fetching layer {}", hex::encode(layer_sha256)))?;
                    let decoder = GzipDecoder::new(progress);
                    let mut splitstream = repo.create_stream(Some(layer_sha256), None);

                    split_async(decoder, &mut splitstream).await?;

                    let layer_id = repo.write_stream(splitstream, None)?;

                    Ok(layer_id)
                },
            );

            // This is useless as it will run the future on the same thread
            //
            // let local = tokio::task::LocalSet::new();
            // local
            //     .run_until(async move {
            //     })
            //     .await;

            // TODO: This needs to be awaited
            // driver.await;

            // let layer_id = [0u8; 32];
            Ok(())
        }
    }

    pub async fn ensure_config(
        &self,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<ContentAndVerity> {
        println!("Called ensure_config");

        let config_sha256 = sha256_from_descriptor(descriptor)?;
        if let Some(config_id) = self.repo.check_stream(&config_sha256)? {
            // We already got this config?  Nice.
            self.progress.println(format!(
                "Already have container config {}",
                hex::encode(config_sha256)
            ))?;
            Ok((config_sha256, config_id))
        } else {
            // We need to add the config to the repo.  We need to parse the config and make sure we
            // have all of the layers first.
            //
            self.progress
                .println(format!("Fetching config {}", hex::encode(config_sha256)))?;
            let raw_config = self.proxy.fetch_config_raw(&self.img).await?;
            let config = ImageConfiguration::from_reader(raw_config.as_slice())?;

            let mut config_maps = DigestMap::new();

            let mut join_set = JoinSet::new();

            for (mld, cld) in zip(manifest_layers, config.rootfs().diff_ids()) {
                let layer_sha256 = sha256_from_digest(cld)?;
                self.ensure_layer(&layer_sha256, mld, &mut join_set).await?;
                // .with_context(|| format!("Failed to fetch layer {cld} via {mld:?}"))?;
            }

            // config_maps.insert(&layer_sha256, &layer_id);

            let result = join_set.join_all().await;

            for (cld, h) in config.rootfs().diff_ids().iter().zip(result) {
                let layer_sha256 = sha256_from_digest(cld)?;
                let layer_id = h?;

                config_maps.insert(&layer_sha256, &layer_id);
            }

            let mut splitstream = self
                .repo
                .create_stream(Some(config_sha256), Some(config_maps));
            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream, None)?;

            Ok((config_sha256, config_id))
        }
    }

    pub async fn pull(&self) -> Result<(Sha256HashValue, Sha256HashValue)> {
        let (_manifest_digest, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        // We need to add the manifest to the repo.  We need to parse the manifest and make
        // sure we have the config first (which will also pull in the layers).
        let manifest = ImageManifest::from_reader(raw_manifest.as_slice())?;
        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        self.ensure_config(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))
    }
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
pub async fn pull(repo: Repository, imgref: &str, reference: Option<&str>) -> Result<()> {
    let repo = Arc::new(repo);

    let op = ImageOp::new(Arc::clone(&repo), imgref).await?;
    let (sha256, id) = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }
    println!("sha256 {}", hex::encode(sha256));
    println!("verity {}", hex::encode(id));
    Ok(())
}

pub fn open_config(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<(ImageConfiguration, DigestMap)> {
    let id = match verity {
        Some(id) => id,
        None => {
            // take the expensive route
            let sha256 = parse_sha256(name)
                .context("Containers must be referred to by sha256 if verity is missing")?;
            &repo
                .check_stream(&sha256)?
                .with_context(|| format!("Object {name} is unknown to us"))?
        }
    };
    let mut stream = repo.open_stream(name, Some(id))?;
    let config = ImageConfiguration::from_reader(&mut stream)?;
    Ok((config, stream.refs))
}

fn hash(bytes: &[u8]) -> Sha256HashValue {
    let mut context = Sha256::new();
    context.update(bytes);
    context.finalize().into()
}

pub fn open_config_shallow(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<ImageConfiguration> {
    match verity {
        // with verity deep opens are just as fast as shallow ones
        Some(id) => Ok(open_config(repo, name, Some(id))?.0),
        None => {
            // we need to manually check the content digest
            let expected_hash = parse_sha256(name)
                .context("Containers must be referred to by sha256 if verity is missing")?;
            let mut stream = repo.open_stream(name, None)?;
            let mut raw_config = vec![];
            stream.read_to_end(&mut raw_config)?;
            ensure!(hash(&raw_config) == expected_hash, "Data integrity issue");
            Ok(ImageConfiguration::from_reader(&mut raw_config.as_slice())?)
        }
    }
}

pub fn write_config(
    repo: &Repository,
    config: &ImageConfiguration,
    refs: DigestMap,
) -> Result<(Sha256HashValue, Sha256HashValue)> {
    let json = config.to_string()?;
    let json_bytes = json.as_bytes();
    let sha256 = hash(json_bytes);
    let mut stream = repo.create_stream(Some(sha256), Some(refs));
    stream.write_inline(json_bytes);
    let id = repo.write_stream(stream, None)?;
    Ok((sha256, id))
}

pub fn seal(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<(Sha256HashValue, Sha256HashValue)> {
    let (mut config, refs) = open_config(repo, name, verity)?;
    let mut myconfig = config.config().clone().context("no config!")?;
    let labels = myconfig.labels_mut().get_or_insert_with(HashMap::new);
    let id = crate::oci::image::create_image(repo, name, None, verity)?;
    labels.insert("containers.composefs.fsverity".to_string(), hex::encode(id));
    config.set_config(Some(myconfig));
    write_config(repo, &config, refs)
}

pub fn mount(
    repo: &Repository,
    name: &str,
    mountpoint: &str,
    verity: Option<&Sha256HashValue>,
) -> Result<()> {
    let config = open_config_shallow(repo, name, verity)?;
    let Some(id) = config.get_config_annotation("containers.composefs.fsverity") else {
        bail!("Can only mount sealed containers");
    };
    repo.mount(id, mountpoint)
}

pub fn meta_layer(repo: &Repository, name: &str, verity: Option<&Sha256HashValue>) -> Result<()> {
    let (config, refs) = open_config(repo, name, verity)?;

    let ids = config.rootfs().diff_ids();
    if ids.len() >= 3 {
        let layer_sha256 = sha256_from_digest(&ids[ids.len() - 2])?;
        let layer_verity = refs.lookup(&layer_sha256).context("bzzt")?;
        repo.merge_splitstream(
            &hex::encode(layer_sha256),
            Some(layer_verity),
            &mut std::io::stdout(),
        )
    } else {
        bail!("No meta layer here");
    }
}

pub fn prepare_boot(
    repo: &Repository,
    name: &str,
    verity: Option<&Sha256HashValue>,
    output_dir: &Path,
) -> Result<()> {
    let (config, refs) = open_config(repo, name, verity)?;

    /* TODO: check created image ID against composefs label on container, if set */
    /* TODO: check created image ID against composefs= .cmdline in UKI or loader entry */
    crate::oci::image::create_image(repo, name, None, verity)?;

    /*
    let layer_digest = config
        .get_config_annotation("containers.composefs.attachments")
        .with_context(|| format!("Can't find attachments layer for container {name}"))?;
    let layer_sha256 = sha256_from_digest(layer_digest)?;
    */

    let ids = config.rootfs().diff_ids();
    ensure!(ids.len() >= 3, "No meta layer here");
    let layer_sha256 = sha256_from_digest(&ids[ids.len() - 2])?;
    let layer_verity = refs
        .lookup(&layer_sha256)
        .with_context(|| "Attachments layer {layer} is not connected to image {name}")?;

    // read the layer into a FileSystem object
    let mut filesystem = crate::image::FileSystem::new();
    let mut split_stream = repo.open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;
    while let Some(entry) = tar::get_entry(&mut split_stream)? {
        image::process_entry(&mut filesystem, entry)?;
    }

    let boot = filesystem.root.recurse("composefs-meta")?.recurse("boot")?;

    write_to_path(repo, boot, output_dir)
}
