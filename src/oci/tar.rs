use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    io::{Read, Seek},
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::PathBuf,
};

use anyhow::{bail, ensure, Result};
use rustix::fs::makedev;
use tar::{Entry, EntryType, Header, PaxExtensions};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    dumpfile, etrace,
    fsverity::{FsVerityHashValue, Sha256HashValue},
    image::{FileSystem, LeafContent, Stat},
    oci::image::process_entry,
    splitstream::{SplitStreamData, SplitStreamReader, SplitStreamWriter},
    util::{read_exactish, read_exactish_async},
    INLINE_CONTENT_MAX,
};

// Keywords for PAX extended header records.
const PAX_PATH: &str = "path";
const PAX_LINKPATH: &str = "linkpath";

fn read_header<R: Read>(reader: &mut R) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish(reader, header.as_mut_bytes())? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

async fn read_header_async(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish_async(reader, header.as_mut_bytes()).await? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split<R: Read>(tar_stream: &mut R, writer: &mut SplitStreamWriter) -> Result<()> {
    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            writer.write_external(&buffer, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

pub async fn split_async(
    mut tar_stream: impl AsyncRead + Unpin,
    writer: &mut SplitStreamWriter<'_>,
) -> Result<()> {
    while let Some(header) = read_header_async(&mut tar_stream).await? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer).await?;

        if header.entry_type() == EntryType::Regular && actual_size > INLINE_CONTENT_MAX {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            writer.write_external(&buffer, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub enum TarItem {
    #[default]
    Directory,
    Leaf(LeafContent),
    Hardlink(OsString),
}

#[derive(Debug, Default)]
pub struct TarEntry {
    pub path: PathBuf,
    pub stat: Stat,
    pub item: TarItem,
}

impl fmt::Display for TarEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.item {
            TarItem::Hardlink(ref target) => dumpfile::write_hardlink(fmt, &self.path, target),
            TarItem::Directory => dumpfile::write_directory(fmt, &self.path, &self.stat, 1),
            TarItem::Leaf(ref content) => {
                dumpfile::write_leaf(fmt, &self.path, &self.stat, content, 1)
            }
        }
    }
}

fn path_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];
    if let Some(name) = pax {
        path.extend(name);
    } else if !gnu.is_empty() {
        path.extend(gnu);
    } else {
        path.extend(short);
    }

    // Drop trailing '/' characters in case of directories.
    // https://github.com/rust-lang/rust/issues/122741
    // path.pop_if(|x| x == &b'/');
    if path.last() == Some(&b'/') {
        path.pop(); // this is Vec<u8>, so that's a single char.
    }

    PathBuf::from(OsString::from_vec(path))
}

fn symlink_target_from_tar(pax: Option<Box<[u8]>>, gnu: Vec<u8>, short: &[u8]) -> OsString {
    if let Some(ref name) = pax {
        OsString::from(OsStr::from_bytes(name))
    } else if !gnu.is_empty() {
        OsString::from_vec(gnu)
    } else {
        OsString::from(OsStr::from_bytes(short))
    }
}

/// Paths with > 100 chars are stored  in pax extensions
/// so, we check if this exists
fn get_path_from_pax<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
    key: &str,
    absolute: bool,
) -> Result<Option<PathBuf>, anyhow::Error> {
    if let Ok(Some(ext)) = entry.pax_extensions() {
        for e in ext {
            let e = e?;

            if e.key()? == key {
                let path = PathBuf::from(e.value()?);
                // convert to absolute path
                return Ok(Some(if absolute {
                    PathBuf::from("/").join(path)
                } else {
                    path
                }));
            };
        }
    };

    Ok(None)
}

fn parse_external_entry<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
) -> Result<TarEntry, anyhow::Error> {
    let header = entry.header();
    let entry_size = header.entry_size()? as usize;

    let mut tar_entry = TarEntry::default();
    tar_entry.stat = header.try_into()?;

    let stored_size = (entry_size + 511) & !511;

    let padding = if stored_size > entry_size {
        stored_size - entry_size
    } else {
        0
    };

    etrace!("Padding: {padding}");

    let mut id = Sha256HashValue::EMPTY;

    // discard the padding
    let mut data = vec![0; id.len() + padding];
    entry.read(&mut data)?;

    id.clone_from_slice(&data[..32]);

    match entry.header().entry_type() {
        EntryType::Regular | EntryType::Continuous => {
            tar_entry.path = {
                if let Some(path) = get_path_from_pax(entry, PAX_PATH, true)? {
                    path
                } else {
                    PathBuf::from("/").join(entry.header().path()?)
                }
            };

            tar_entry.item = TarItem::Leaf(LeafContent::ExternalFile(id, entry_size as u64));

            etrace!("Read external data: {}", hex::encode(id));

            // Next entry will be read after we process this one
            // TODO:? We can implement iterator for Splitstream

            etrace!("After external entry processing");
        }

        _ => bail!(
            "Unsupported external-chunked entry {:?} {}",
            entry.header(),
            hex::encode(id)
        ),
    };

    return Ok(tar_entry);
}

fn parse_internal_entry<R: Read>(
    entry: &mut Entry<'_, &mut SplitStreamReader<R>>,
) -> Result<TarEntry, anyhow::Error> {
    let header = entry.header();
    let entry_size = header.entry_size()? as usize;

    let mut tar_entry = TarEntry::default();
    tar_entry.stat = header.try_into()?;

    etrace!(
        "gonna parse some inline content: type: {:#?}, path: {:?}",
        header.entry_type(),
        header.path()
    );

    match header.entry_type() {
        EntryType::Regular | EntryType::Continuous => {
            let mut content = vec![0; (entry_size + 511) & 511];
            entry.read(&mut content)?;

            tar_entry.path = {
                if let Some(path) = get_path_from_pax(entry, PAX_LINKPATH, true)? {
                    path
                } else {
                    PathBuf::from("/").join(entry.header().path()?)
                }
            };

            etrace!("{:?}", content);

            tar_entry.item = TarItem::Leaf(LeafContent::InlineFile(content));
        }

        EntryType::Link | EntryType::Symlink => {
            let is_hard_link = entry.header().entry_type() == EntryType::Link;

            tar_entry.path = {
                // only get absolute path for hard links, for symlinks we want relative paths
                if let Some(path) = get_path_from_pax(entry, PAX_LINKPATH, is_hard_link)? {
                    etrace!("Got path '{path:?}' from pax for symlink");
                    path
                } else {
                    let link_name = entry.header().link_name()?;

                    match link_name {
                        Some(l) => PathBuf::from("/").join(l),
                        None => bail!("Hard link without a path?"),
                    }
                }
            };

            tar_entry.item = if is_hard_link {
                TarItem::Hardlink(tar_entry.path.clone().into())
            } else {
                TarItem::Leaf(LeafContent::Symlink(tar_entry.path.clone().into()))
            };
        }

        EntryType::GNULongName => todo!(),
        EntryType::GNULongLink => todo!(),
        EntryType::GNUSparse => todo!(),
        EntryType::XGlobalHeader => todo!(),

        EntryType::Fifo => tar_entry.item = TarItem::Leaf(LeafContent::Fifo),

        EntryType::Char | EntryType::Block => {
            let (maj, min) = match (header.device_major()?, header.device_minor()?) {
                (Some(major), Some(minor)) => (major, minor),

                _ => bail!("Device entry without device numbers?"),
            };

            tar_entry.item = if header.entry_type() == EntryType::Char {
                TarItem::Leaf(LeafContent::CharacterDevice(makedev(maj, min)))
            } else {
                TarItem::Leaf(LeafContent::BlockDevice(makedev(maj, min)))
            };
        }

        EntryType::Directory => {
            tar_entry.path = {
                if let Some(path) = get_path_from_pax(entry, PAX_PATH, true)? {
                    path
                } else {
                    PathBuf::from("/").join(entry.header().path()?)
                }
            };

            tar_entry.item = TarItem::Directory;
        }

        EntryType::XHeader => {}

        _ => todo!(),
    };

    return Ok(tar_entry);
}

pub fn get_entry_new<R: Read>(
    // TODO: pass an archive here
    splitstream_reader: &mut SplitStreamReader<R>,
    filesystem: &mut FileSystem,
) -> Result<()> {
    splitstream_reader.prep_for_archive_extract();

    // We need to keep creating a new archive so that it reads a header for us
    // The tar crate internally keeps track of the previous header and tries to 
    // skip the content length found in the previous header. 
    // This is a problem for external entries, as if an external entry has 10240 bytes
    // but we only store 32 bytes + some padding; on next iteration of an entry, the tar
    // crate will try to skip the next (10240 + 511) & !511 bytes
    let mut archive = tar::Archive::new(&mut *splitstream_reader);

    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => todo!(),
    };

    for entry in entries.peekable() {
        etrace!("----------------------------------------");

        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let mut v = [0u8; 512];
                splitstream_reader.read(&mut v);
                etrace!("Next 512 bytes: {v:?}");
                bail!("Error while reading entry: {e:?}");
            }
        };

        etrace!("entry header: {:?}", entry.header());

        let header = entry.header();
        let entry_size = header.entry_size()? as usize;
        etrace!("entry_size: {entry_size}");

        // An external ref, i.e. a SHA256 hash
        let tar_entry = if entry_size > INLINE_CONTENT_MAX {
            parse_external_entry(&mut entry)?
        } else {
            parse_internal_entry(&mut entry)?
        };

        etrace!(
            "tar_entry: {} {tar_entry:?}",
            if entry_size > INLINE_CONTENT_MAX {
                "external"
            } else {
                "internal"
            }
        );

        // process_entry(filesystem, tar_entry)?;
    }

    Ok(())
}

pub fn get_entry<R: Read>(reader: &mut SplitStreamReader<R>) -> Result<Option<TarEntry>> {
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut gnu_longname: Vec<u8> = vec![];
    let mut pax_longlink: Option<Box<[u8]>> = None;
    let mut pax_longname: Option<Box<[u8]>> = None;
    let mut xattrs = BTreeMap::new();

    loop {
        let mut buf = [0u8; 512];
        if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
            return Ok(None);
        }

        let header = tar::Header::from_byte_slice(&buf);
        assert!(header.as_ustar().is_some());

        let size = header.entry_size()?;

        etrace!(
            "actual_size: {size}, stored_size: {}",
            ((size + 511) & !511)
        );

        let item = match reader.read_exact(size as usize, ((size + 511) & !511) as usize)? {
            SplitStreamData::External(id) => match header.entry_type() {
                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        size as usize > INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a small ({size} byte) file external"
                    );
                    etrace!("External file: {}", hex::encode(id));
                    TarItem::Leaf(LeafContent::ExternalFile(id, size))
                }
                _ => bail!(
                    "Unsupported external-chunked entry {:?} {}",
                    header,
                    hex::encode(id)
                ),
            },

            SplitStreamData::Inline(content) => match header.entry_type() {
                EntryType::GNULongLink => {
                    gnu_longlink.extend(content);
                    continue;
                }

                EntryType::GNULongName => {
                    gnu_longname.extend(content);
                    continue;
                }

                EntryType::XGlobalHeader => {
                    todo!();
                }

                EntryType::XHeader => {
                    for item in PaxExtensions::new(&content) {
                        let extension = item?;
                        let key = extension.key()?;
                        let value = Box::from(extension.value_bytes());

                        if key == "path" {
                            pax_longname = Some(value);
                        } else if key == "linkpath" {
                            pax_longlink = Some(value);
                        } else if let Some(xattr) = key.strip_prefix("SCHILY.xattr.") {
                            xattrs.insert(Box::from(OsStr::new(xattr)), value);
                        }
                    }
                    continue;
                }

                EntryType::Directory => TarItem::Directory,

                EntryType::Regular | EntryType::Continuous => {
                    ensure!(
                        content.len() <= INLINE_CONTENT_MAX,
                        "Splitstream incorrectly stored a large ({} byte) file inline",
                        content.len()
                    );

                    // etrace!("Regular or Continuous file. Content: {content:?}");

                    TarItem::Leaf(LeafContent::InlineFile(content))
                }

                EntryType::Link => TarItem::Hardlink({
                    let Some(link_name) = header.link_name_bytes() else {
                        bail!("link without a name?")
                    };
                    OsString::from(path_from_tar(pax_longlink, gnu_longlink, &link_name))
                }),

                EntryType::Symlink => TarItem::Leaf(LeafContent::Symlink({
                    let Some(link_name) = header.link_name_bytes() else {
                        bail!("symlink without a name?")
                    };
                    symlink_target_from_tar(pax_longlink, gnu_longlink, &link_name)
                })),

                EntryType::Block => TarItem::Leaf(LeafContent::BlockDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),

                EntryType::Char => TarItem::Leaf(LeafContent::CharacterDevice(
                    match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                )),

                EntryType::Fifo => TarItem::Leaf(LeafContent::Fifo),
                _ => {
                    todo!("Unsupported entry {:?}", header);
                }
            },
        };

        return Ok(Some(TarEntry {
            path: path_from_tar(pax_longname, gnu_longname, &header.path_bytes()),
            stat: Stat {
                st_uid: header.uid()? as u32,
                st_gid: header.gid()? as u32,
                st_mode: header.mode()?,
                st_mtim_sec: header.mtime()? as i64,
                xattrs: RefCell::new(xattrs),
            },
            item,
        }));
    }
}
