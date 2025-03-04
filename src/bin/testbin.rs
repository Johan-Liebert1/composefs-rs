use std::{fs::File, io::Read, path::PathBuf};

use tar::Archive;

const FILE_NAME: &str = "/home/ppoudyal/RedHat/composefs-rs/src/bin/test.tar";

fn main() {
    let p = PathBuf::from("/").join(FILE_NAME);
    println!("p: {p:#?}");

    let file = File::open(FILE_NAME).unwrap();

    // file.seek(std::io::SeekFrom::Start(16)).unwrap();

    // let zstd_decoder = ZstdDecoder::new(file).unwrap();

    let mut a = Archive::new(file);

    let entries = a.entries();

    // if entries.is_err() {
    //     println!("Entry {fname} failed. Err: {:?}", entries.err());
    // }

    for tar_entry in entries.unwrap() {
        let mut entry = match tar_entry {
            Ok(f) => f,
            Err(err) => {
                println!("Something went wrong with file. Err: {err:?}");
                continue;
            }
        };

        if let Ok(Some(ext)) = entry.pax_extensions() {
            for e in ext {
                if let Ok(path) = e {
                    println!("key: {:?}", path.key());
                    println!("value: {:?}", path.value());
                }
            }
        }

        let header = entry.header();

        println!("{:#?}", header);
        println!("EntryType: {:#?}", header.entry_type());

        println!("path: {:?}", header.path().unwrap());
        println!("size: {}", header.size().unwrap());

        let mut s = String::new();
        entry.read_to_string(&mut s).unwrap();
        println!("File: {}\n\n\n", s);
    }
}
