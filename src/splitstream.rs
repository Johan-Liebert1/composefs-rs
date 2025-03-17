/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    io::{self, BufReader, Read, Write},
    process::exit,
    sync::{mpsc::Sender, Arc, Mutex},
    thread::{self, JoinHandle},
};

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::{ensure_object_new, Repository},
    util::read_exactish,
};

#[derive(Debug)]
pub struct DigestMapEntry {
    pub body: Sha256HashValue,
    pub verity: Sha256HashValue,
}

#[derive(Debug)]
pub struct DigestMap {
    pub map: Vec<DigestMapEntry>,
}

impl Default for DigestMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DigestMap {
    pub fn new() -> Self {
        DigestMap { map: vec![] }
    }

    pub fn lookup(&self, body: &Sha256HashValue) -> Option<&Sha256HashValue> {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => Some(&self.map[idx].verity),
            Err(..) => None,
        }
    }

    pub fn insert(&mut self, body: &Sha256HashValue, verity: &Sha256HashValue) {
        match self.map.binary_search_by_key(body, |e| e.body) {
            Ok(idx) => assert_eq!(self.map[idx].verity, *verity), // or else, bad things...
            Err(idx) => self.map.insert(
                idx,
                DigestMapEntry {
                    body: *body,
                    verity: *verity,
                },
            ),
        }
    }
}

/// (ExternalContent, InlineContent)
pub(crate) type SplitStreamWriterSenderData = (Vec<u8>, Vec<u8>);

pub struct SplitStreamWriter<'a> {
    repo: &'a Repository,
    pub(crate) inline_content: Arc<Mutex<Vec<u8>>>,
    writer: Encoder<'a, Vec<u8>>,
    pub(crate) sha256: Option<(Sha256, Sha256HashValue)>,
    pub(crate) object_sender: Sender<EnsureObjectMessages>,
    pub join_handle: JoinHandle<()>,
}

impl std::fmt::Debug for SplitStreamWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writer doesn't impl Debug
        f.debug_struct("SplitStreamWriter")
            .field("repo", &self.repo)
            .field("inline_content", &self.inline_content)
            .field("sha256", &self.sha256)
            .finish()
    }
}

pub(crate) enum WriterMessages {
    /// (Digest, InlineData, ExternalData)
    WriteData((Sha256HashValue, Vec<u8>, Vec<u8>)),
    Finish(Vec<u8>),
}

pub(crate) enum EnsureObjectMessages {
    Data(SplitStreamWriterSenderData),
    Finish(Vec<u8>),
}

impl SplitStreamWriter<'_> {
    pub fn new(
        repo: &Repository,
        refs: Option<DigestMap>,
        sha256: Option<Sha256HashValue>,
        done_chan_sender: Sender<(Sha256HashValue, Sha256HashValue)>,
    ) -> SplitStreamWriter {
        let (object_sender, object_receiver) = std::sync::mpsc::channel::<EnsureObjectMessages>();
        let (writer_chan_sender, write_chan_receiver) =
            std::sync::mpsc::channel::<WriterMessages>();

        let inline_content = Arc::new(Mutex::new(vec![]));

        let cloned_sender = object_sender.clone();
        let repository = repo.repository.clone();

        let handle = thread::spawn({
            let repository = repo.repository.clone();

            move || {
                // TODO: Handle error
                let _ = ensure_object_new(repository, object_receiver, writer_chan_sender);
            }
        });

        thread::spawn(move || {
            // SAFETY: we surely can't get an error writing the header to a Vec<u8>
            let mut writer = Encoder::new(vec![], 3).unwrap();
            writer.set_target_cblock_size(Some(1024)).unwrap();

            let mut sha256_builder = sha256.map(|x| (Sha256::new(), x));

            fn flush_inline(
                writer: &mut impl Write,
                inline_content: Vec<u8>,
                sha256_builder: &mut Option<(Sha256, Sha256HashValue)>,
            ) {
                if inline_content.is_empty() {
                    return;
                }

                if let Some((sha256, ..)) = sha256_builder {
                    sha256.update(&inline_content);
                }

                if let Err(e) =
                    SplitStreamWriter::write_fragment(writer, inline_content.len(), &inline_content)
                {
                    println!("write_fragment err while writing inline content: {e:?}")
                }
            }

            match refs {
                Some(DigestMap { map }) => {
                    writer.write_all(&(map.len() as u64).to_le_bytes()).unwrap();

                    println!("while writing map.len(): {}", map.len());

                    for ref entry in map {
                        writer.write_all(&entry.body).unwrap();
                        writer.write_all(&entry.verity).unwrap();
                    }
                }

                None => {
                    writer.write_all(&0u64.to_le_bytes()).unwrap();
                }
            }

            while let Ok(data) = write_chan_receiver.recv() {
                match data {
                    WriterMessages::WriteData((recv_data, inline_content, external_content)) => {
                        flush_inline(&mut writer, inline_content, &mut sha256_builder);

                        if let Some((sha256, ..)) = &mut sha256_builder {
                            sha256.update(external_content);
                        }

                        // write the actual data
                        if let Err(e) =
                            SplitStreamWriter::write_fragment(&mut writer, 0, &recv_data)
                        {
                            println!("write_fragment err while writing external content: {e:?}")
                        }
                    }

                    WriterMessages::Finish(inline_content) => {
                        flush_inline(&mut writer, inline_content, &mut sha256_builder);

                        let finished = writer.finish().unwrap();

                        if let Some((context, expected)) = sha256_builder {
                            let final_sha = Into::<Sha256HashValue>::into(context.finalize());

                            if final_sha != expected {
                                println!(
                                    "\x1b[31m===\nContent doesn't have expected SHA256 hash value!\nExpected: {}, final: {}\n===\n\x1b[0m",
                                    hex::encode(expected),
                                    hex::encode(final_sha)
                                );

                                return;
                            }
                        }

                        if let Err(e) =
                            cloned_sender.send(EnsureObjectMessages::Data((finished, vec![])))
                        {
                            println!("Failed to finish writer. Err: {e}");
                        };

                        break;
                    }
                }
            }

            // wait for the final message
            // this should also be fine as mpsc::channel messages are always queued in case there
            // is no receiver receiving yet
            while let Ok(data) = write_chan_receiver.recv() {
                match data {
                    WriterMessages::WriteData((digest, _, _)) => {
                        // let Some((.., ref sha256)) = sha256_builder else {
                        //     // bail!("Writer doesn't have sha256 enabled");
                        //     println!("\x1b[31mWriter doesn't have sha256 enabled\x1b[0m");
                        //     return;
                        // };

                        let stream_path = format!(
                            "streams/{}",
                            hex::encode(sha256.unwrap_or(/* TODO: Crash here... */ [0; 32]))
                        );

                        let object_path = Repository::format_object_path(&digest);
                        Repository::ensure_symlink_new(&stream_path, &object_path, repository);

                        // if let Some(name) = reference {
                        //     let reference_path = format!("streams/refs/{name}");
                        //     self.symlink(&reference_path, &stream_path)?;
                        // }

                        if let Err(e) = done_chan_sender.send((sha256.unwrap_or([0; 32]), digest)) {
                            println!("Failed to send final digest with err: {e:?}");
                        }

                        break;
                    }

                    WriterMessages::Finish(..) => panic!("Received two finish requests"),
                }
            }

            drop(cloned_sender);
            drop(done_chan_sender);
        });

        SplitStreamWriter {
            repo,
            inline_content,
            // not used
            writer: Encoder::new(vec![], 0).unwrap(),
            object_sender,
            // not used
            sha256: sha256.map(|x| (Sha256::new(), x)),
            join_handle: handle,
        }
    }

    fn write_fragment(writer: &mut impl Write, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        let mut inline = self.inline_content.lock().unwrap();

        if !inline.is_empty() {
            SplitStreamWriter::write_fragment(&mut self.writer, inline.len(), &inline)?;
            *inline = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
        }
        self.inline_content.lock().unwrap().extend(data);
    }

    /// write a reference to external data to the stream.  If the external data had padding in the
    /// stream which is not stored in the object then pass it here as well and it will be stored
    /// inline after the reference.
    fn write_reference(&mut self, reference: Sha256HashValue, padding: Vec<u8>) -> Result<()> {
        // Flush the inline data before we store the external reference.  Any padding from the
        // external data becomes the start of a new inline block.
        self.flush_inline(padding)?;

        SplitStreamWriter::write_fragment(&mut self.writer, 0, &reference)
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>) -> Result<()> {
        if let Some((ref mut sha256, ..)) = self.sha256 {
            sha256.update(data);
            sha256.update(&padding);
        }

        let mut mutex_guard = self.inline_content.lock().unwrap();
        let inline_content = std::mem::replace(&mut *mutex_guard, padding);
        drop(mutex_guard); // unlock mutex

        // TODO: ack_channel is mpsc so cloning it should be fine
        if let Err(e) = self
            .object_sender
            .send(EnsureObjectMessages::Data((data.to_vec(), inline_content)))
        {
            println!("is thread closed: {}", self.join_handle.is_finished());
            println!("Falied to send message. Err: {e:?}");
        }

        Ok(())

        // .context("Falied to send data on channel in write_external")?;
        // let id = self.repo.ensure_object(data)?;
        // self.write_reference([0; 32], padding)
    }

    pub fn done(mut self) -> Result<Sha256HashValue> {
        self.flush_inline(vec![])?;

        if let Some((context, expected)) = self.sha256 {
            if Into::<Sha256HashValue>::into(context.finalize()) != expected {
                bail!("Content doesn't have expected SHA256 hash value!");
            }
        }

        self.repo.ensure_object(&self.writer.finish()?)
    }
}

#[derive(Debug)]
pub enum SplitStreamData {
    Inline(Vec<u8>),
    External(Sha256HashValue),
}

// utility class to help read splitstreams
pub struct SplitStreamReader<R: Read> {
    decoder: Decoder<'static, BufReader<R>>,
    pub refs: DigestMap,
    inline_bytes: usize,
}

impl<R: Read> std::fmt::Debug for SplitStreamReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // decoder doesn't impl Debug
        f.debug_struct("SplitStreamReader")
            .field("refs", &self.refs)
            .field("inline_bytes", &self.inline_bytes)
            .finish()
    }
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<Option<usize>> {
    let mut buf = [0u8; 8];
    if read_exactish(reader, &mut buf)? {
        Ok(Some(u64::from_le_bytes(buf) as usize))
    } else {
        Ok(None)
    }
}

fn read_into_vec(reader: &mut impl Read, vec: &mut Vec<u8>, size: usize) -> Result<()> {
    unsafe {
        vec.truncate(0);
        vec.reserve(size);
        reader.read_exact(std::slice::from_raw_parts_mut(vec.as_mut_ptr(), size))?;
        vec.set_len(size);
    }
    Ok(())
}

enum ChunkType {
    Eof,
    Inline,
    External(Sha256HashValue),
}

impl<R: Read> SplitStreamReader<R> {
    pub fn new(reader: R) -> Result<SplitStreamReader<R>> {
        let mut decoder = Decoder::new(reader)?;

        let n_map_entries = {
            let mut buf = [0u8; 8];
            decoder.read_exact(&mut buf)?;
            u64::from_le_bytes(buf)
        } as usize;

        let mut refs = DigestMap {
            map: Vec::with_capacity(n_map_entries),
        };
        for _ in 0..n_map_entries {
            let mut body = [0u8; 32];
            let mut verity = [0u8; 32];

            decoder.read_exact(&mut body)?;
            decoder.read_exact(&mut verity)?;
            refs.map.push(DigestMapEntry { body, verity });
        }

        Ok(SplitStreamReader {
            decoder,
            refs,
            inline_bytes: 0,
        })
    }

    fn ensure_chunk(
        &mut self,
        eof_ok: bool,
        ext_ok: bool,
        expected_bytes: usize,
    ) -> Result<ChunkType> {
        if self.inline_bytes == 0 {
            match read_u64_le(&mut self.decoder)? {
                None => {
                    if !eof_ok {
                        bail!("Unexpected EOF when parsing splitstream");
                    }
                    return Ok(ChunkType::Eof);
                }
                Some(0) => {
                    if !ext_ok {
                        bail!("Unexpected external reference when parsing splitstream");
                    }
                    let mut id = Sha256HashValue::EMPTY;
                    self.decoder.read_exact(&mut id)?;
                    return Ok(ChunkType::External(id));
                }
                Some(size) => {
                    self.inline_bytes = size;
                }
            }
        }

        if self.inline_bytes < expected_bytes {
            bail!("Unexpectedly small inline content when parsing splitstream");
        }

        Ok(ChunkType::Inline)
    }

    /// Reads the exact number of inline bytes
    /// Assumes that the data cannot be split across chunks
    pub fn read_inline_exact(&mut self, buffer: &mut [u8]) -> Result<bool> {
        if let ChunkType::Inline = self.ensure_chunk(true, false, buffer.len())? {
            self.decoder.read_exact(buffer)?;
            self.inline_bytes -= buffer.len();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn discard_padding(&mut self, size: usize) -> Result<()> {
        let mut buf = [0u8; 512];
        assert!(size <= 512);
        self.ensure_chunk(false, false, size)?;
        self.decoder.read_exact(&mut buf[0..size])?;
        self.inline_bytes -= size;
        Ok(())
    }

    pub fn read_exact(
        &mut self,
        actual_size: usize,
        stored_size: usize,
    ) -> Result<SplitStreamData> {
        if let ChunkType::External(id) = self.ensure_chunk(false, true, stored_size)? {
            // ...and the padding
            if actual_size < stored_size {
                self.discard_padding(stored_size - actual_size)?;
            }
            Ok(SplitStreamData::External(id))
        } else {
            let mut content = vec![];
            read_into_vec(&mut self.decoder, &mut content, stored_size)?;
            content.truncate(actual_size);
            self.inline_bytes -= stored_size;
            Ok(SplitStreamData::Inline(content))
        }
    }

    pub fn cat(
        &mut self,
        output: &mut impl Write,
        mut load_data: impl FnMut(&Sha256HashValue) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let mut buffer = vec![];

        loop {
            match self.ensure_chunk(true, true, 0)? {
                ChunkType::Eof => break Ok(()),
                ChunkType::Inline => {
                    read_into_vec(&mut self.decoder, &mut buffer, self.inline_bytes)?;
                    self.inline_bytes = 0;
                    output.write_all(&buffer)?;
                }
                ChunkType::External(ref id) => {
                    output.write_all(&load_data(id)?)?;
                }
            }
        }
    }

    pub fn get_object_refs(&mut self, mut callback: impl FnMut(&Sha256HashValue)) -> Result<()> {
        let mut buffer = vec![];

        for entry in &self.refs.map {
            callback(&entry.verity);
        }

        loop {
            match self.ensure_chunk(true, true, 0)? {
                ChunkType::Eof => break Ok(()),
                ChunkType::Inline => {
                    read_into_vec(&mut self.decoder, &mut buffer, self.inline_bytes)?;
                    self.inline_bytes = 0;
                }
                ChunkType::External(ref id) => {
                    callback(id);
                }
            }
        }
    }

    pub fn get_stream_refs(&mut self, mut callback: impl FnMut(&Sha256HashValue)) {
        for entry in &self.refs.map {
            callback(&entry.body);
        }
    }

    pub fn lookup(&self, body: &Sha256HashValue) -> Result<&Sha256HashValue> {
        match self.refs.lookup(body) {
            Some(id) => Ok(id),
            None => bail!("Reference is not found in splitstream"),
        }
    }
}

impl<F: Read> Read for SplitStreamReader<F> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        match self.ensure_chunk(true, false, 1) {
            Ok(ChunkType::Eof) => Ok(0),
            Ok(ChunkType::Inline) => {
                let n_bytes = std::cmp::min(data.len(), self.inline_bytes);
                self.decoder.read_exact(&mut data[0..n_bytes])?;
                self.inline_bytes -= n_bytes;
                Ok(n_bytes)
            }
            Ok(ChunkType::External(..)) => unreachable!(),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }
}
