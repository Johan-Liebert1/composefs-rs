use std::{
    ffi::OsStr,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::Component,
    process::{
        Command,
        Stdio
    },
    rc::Rc,
};

use anyhow::{
    Result,
    bail,
};
use crate::{
    dumpfile::write_dumpfile,
    fsverity::Sha256HashValue,
    image::{
        FileSystem,
        Leaf,
    },
    oci,
    repository::Repository,
};

pub fn process_entry(filesystem: &mut FileSystem, entry: oci::tar::TarEntry) -> Result<()> {
    let mut components = entry.path.components();

    let Some(Component::Normal(filename)) = components.next_back() else { bail!("Empty filename") };

    let mut dir = &mut filesystem.root;
    for component in components {
        if let Component::Normal(name) = component {
            dir = dir.recurse(name)?;
        }
    }

    let bytes = filename.as_bytes();
    if let Some(whiteout) = bytes.strip_prefix(b".wh.") {
        if whiteout == b".wh.opq" {  // complete name is '.wh..wh.opq'
            dir.remove_all()
        } else {
            dir.remove(OsStr::from_bytes(whiteout))
        }
    } else {
        match entry.item {
            oci::tar::TarItem::Directory => {
                dir.mkdir(filename, entry.stat)
            },
            oci::tar::TarItem::Leaf(content) => {
                dir.insert(filename, Rc::new(Leaf { stat: entry.stat, content }))
            },
            oci::tar::TarItem::Hardlink(ref target) => {
                // TODO: would be nice to do this inline, but borrow checker doesn't like it
                filesystem.hardlink(&entry.path, target)?;
            },
        }
    }

    Ok(())
}

pub fn compose_filesystem(repo: &Repository, layers: &[String]) -> Result<FileSystem> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer, None)?;
        while let Some(entry) = oci::tar::get_entry(&mut split_stream)? {
           process_entry(&mut filesystem, entry)?;
        }
    }

    Ok(filesystem)
}

pub fn create_dumpfile(repo: &Repository, layers: &[String]) -> Result<()> {
    let filesystem = compose_filesystem(repo, layers)?;
    let mut stdout = std::io::stdout();
    write_dumpfile(&mut stdout, &filesystem)?;
    Ok(())
}

pub fn create_image(repo: &Repository, name: &str, layers: &Vec<String>) -> Result<Sha256HashValue> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer, None)?;
        while let Some(entry) = oci::tar::get_entry(&mut split_stream)? {
           process_entry(&mut filesystem, entry)?;
        }
    }

    let mut mkcomposefs = Command::new("mkcomposefs")
        .args(["--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = mkcomposefs.stdin.take().unwrap();
    write_dumpfile(&mut stdin, &filesystem)?;
    drop(stdin);

    let mut stdout = mkcomposefs.stdout.take().unwrap();
    let mut image = vec![];
    stdout.read_to_end(&mut image)?;
    drop(stdout);

    if !mkcomposefs.wait()?.success() {
        bail!("mkcomposefs failed");
    };

    repo.write_image(name, &image)
}

#[cfg(test)]
use std::{
    io::BufRead,
    path::PathBuf,
};
#[cfg(test)]
use crate::image::{
    LeafContent,
    Stat,
};

#[cfg(test)]
fn file_entry(path: &str) -> oci::tar::TarEntry {
    oci::tar::TarEntry {
        path: PathBuf::from(path),
        stat: Stat { st_mode: 0o644, st_uid: 0, st_gid: 0, st_mtim_sec: 0, xattrs: vec![]},
        item: oci::tar::TarItem::Leaf(LeafContent::InlineFile(vec![])),
    }
}

#[cfg(test)]
fn dir_entry(path: &str) -> oci::tar::TarEntry {
    oci::tar::TarEntry {
        path: PathBuf::from(path),
        stat: Stat { st_mode: 0o755, st_uid: 0, st_gid: 0, st_mtim_sec: 0, xattrs: vec![]},
        item: oci::tar::TarItem::Directory,
    }
}

#[cfg(test)]
fn assert_files(fs: &FileSystem, expected: &[&str]) -> Result<()> {
    let mut out = vec![];
    write_dumpfile(&mut out, fs)?;
    let actual: Vec<String> = out
        .lines()
        .map(|line| line.unwrap().split_once(' ').unwrap().0.into() )
        .collect();

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn test_process_entry() -> Result<()> {
    let mut fs = FileSystem::new();

    // both with and without leading slash should be supported
    process_entry(&mut fs, dir_entry("/a"))?;
    process_entry(&mut fs, dir_entry("b"))?;
    process_entry(&mut fs, dir_entry("c"))?;
    assert_files(&fs, &["/", "/a", "/b", "/c"])?;

    // add some files
    process_entry(&mut fs, file_entry("/a/b"))?;
    process_entry(&mut fs, file_entry("/a/c"))?;
    process_entry(&mut fs, file_entry("/b/a"))?;
    process_entry(&mut fs, file_entry("/b/c"))?;
    process_entry(&mut fs, file_entry("/c/a"))?;
    process_entry(&mut fs, file_entry("/c/c"))?;
    assert_files(&fs, &["/", "/a", "/a/b", "/a/c", "/b", "/b/a", "/b/c", "/c", "/c/a", "/c/c"])?;

    // try some whiteouts
    process_entry(&mut fs, file_entry(".wh.a"))?;  // entire dir
    process_entry(&mut fs, file_entry("/b/.wh..wh.opq"))?;  // opaque dir
    process_entry(&mut fs, file_entry("/c/.wh.c"))?;  // single file
    assert_files(&fs, &["/", "/b", "/c", "/c/a"])?;

    Ok(())
}
