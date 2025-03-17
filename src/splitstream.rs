/* Implementation of the Split Stream file format
 *
 * See doc/splitstream.md
 */

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    io::{BufReader, Read, Write},
    thread::{self, JoinHandle},
};

use crossbeam::channel::Sender;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use zstd::stream::{read::Decoder, write::Encoder};

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
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

pub struct SplitStreamWriter<'a> {
    repo: &'a Repository,
    pub(crate) inline_content: Vec<u8>,
    writer: Encoder<'a, Vec<u8>>,
    pub(crate) sha256: Option<(Sha256, Sha256HashValue)>,
    pub(crate) object_sender: Sender<EnsureObjectMessages>,
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

pub(crate) struct FinishMessage {
    pub(crate) data: Vec<u8>,
    pub(crate) total_msgs: usize,
}

#[derive(Eq)]
pub(crate) struct WriterMessagesData {
    digest: Sha256HashValue,
    inline_content: Vec<u8>,
    external_data: Vec<u8>,
    seq_num: usize,
}

pub(crate) enum WriterMessages {
    WriteData(WriterMessagesData),
    Finish(FinishMessage),
}

impl PartialEq for WriterMessagesData {
    fn eq(&self, other: &Self) -> bool {
        self.seq_num.eq(&other.seq_num)
    }
}

impl PartialOrd for WriterMessagesData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.seq_num.partial_cmp(&other.seq_num)
    }
}

impl Ord for WriterMessagesData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq_num.cmp(&other.seq_num)
    }
}

pub(crate) struct SplitStreamWriterSenderData {
    pub(crate) external_data: Vec<u8>,
    pub(crate) inline_content: Vec<u8>,
    pub(crate) seq_num: usize,
}
pub(crate) enum EnsureObjectMessages {
    Data(SplitStreamWriterSenderData),
    Finish(FinishMessage),
}

impl SplitStreamWriter<'_> {
    pub fn new(
        repo: &Repository,
        refs: Option<DigestMap>,
        sha256: Option<Sha256HashValue>,
        layer_size: u64,
        done_chan_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
    ) -> SplitStreamWriter {
        let (object_sender, object_receiver) =
            crossbeam::channel::unbounded::<EnsureObjectMessages>();

        let (writer_chan_sender, write_chan_receiver) =
            crossbeam::channel::unbounded::<WriterMessages>();

        let inline_content = vec![];

        let cloned_sender = object_sender.clone();

        // spawn a thread for every ~100MB of data. This is completely arbitrary
        let num_threads = ((layer_size / (1024 * 1024)) / 100).max(1);

        println!("layer_size: {layer_size}");
        println!("num_threads: {num_threads}");

        let join_handles: Vec<JoinHandle<()>> = (0..num_threads)
            .map(|_| {
                thread::spawn({
                    let repository = repo.try_clone().unwrap();
                    let object_receiver = object_receiver.clone();
                    let writer_chan_sender = writer_chan_sender.clone();

                    let sha = hex::encode(sha256.unwrap().clone());

                    move || {
                        while let Ok(data) = object_receiver.recv() {
                            match data {
                                EnsureObjectMessages::Data(data) => {
                                    let digest_result = repository.ensure_object(&data.external_data);

                                    let msg = WriterMessagesData{
                                        // TODO: Handle error
                                        digest: digest_result.unwrap(),
                                        inline_content:data.inline_content,
                                        external_data:data.external_data,
                                        seq_num: data.seq_num
                                    };

                                    if let Err(e) = writer_chan_sender.send(WriterMessages::WriteData(msg))
                                    {
                                        println!(
                                            "Failed to ack message at the end for layer {sha}. Err: {}",
                                            e.to_string()
                                        );
                                    };
                                }

                                EnsureObjectMessages::Finish(final_msg) => {
                                    writer_chan_sender.send(WriterMessages::Finish(final_msg));
                                },
                            }
                        }
                    }
                })
            })
            .collect();

        thread::spawn({
            let repository = repo.try_clone().unwrap();

            move || {
                // SAFETY: we surely can't get an error writing the header to a Vec<u8>
                let mut writer = Encoder::new(vec![], 0).unwrap();
                let mut sha256_builder = sha256.map(|x| (Sha256::new(), x));

                let mut last = 0;
                let mut heap: BinaryHeap<Reverse<WriterMessagesData>> = BinaryHeap::new();

                let mut final_message: Option<FinishMessage> = None;

                fn flush_inline(
                    writer: &mut impl Write,
                    inline_content: &Vec<u8>,
                    sha256_builder: &mut Option<(Sha256, Sha256HashValue)>,
                ) {
                    if inline_content.is_empty() {
                        return;
                    }

                    if let Some((sha256, ..)) = sha256_builder {
                        sha256.update(&inline_content);
                    }

                    if let Err(e) = SplitStreamWriter::write_fragment(
                        writer,
                        inline_content.len(),
                        &inline_content,
                    ) {
                        println!("write_fragment err while writing inline content: {e:?}")
                    }
                }

                fn write_message(
                    heap: &mut BinaryHeap<Reverse<WriterMessagesData>>,
                    writer: &mut impl Write,
                    sha256_builder: &mut Option<(Sha256, Sha256HashValue)>,
                    mut last: usize,
                ) -> usize {
                    while let Some(data) = heap.peek() {
                        if data.0.seq_num != last {
                            break;
                        }

                        let data = heap.pop().unwrap();

                        flush_inline(writer, &data.0.inline_content, sha256_builder);

                        if let Some((sha256, ..)) = sha256_builder {
                            sha256.update(data.0.external_data);
                        }

                        // write the actual data
                        if let Err(e) = SplitStreamWriter::write_fragment(writer, 0, &data.0.digest)
                        {
                            println!("write_fragment err while writing external content: {e:?}")
                        }

                        last += 1;
                    }

                    return last;
                }

                fn handle_received_message(
                    recv_data: WriterMessagesData,
                    heap: &mut BinaryHeap<Reverse<WriterMessagesData>>,
                ) {
                    heap.push(Reverse(recv_data));
                }

                fn handle_final_message(
                    inline_content: Vec<u8>,
                    mut writer: Encoder<'static, Vec<u8>>,
                    mut sha256_builder: Option<(Sha256, Sha256HashValue)>,
                    cloned_sender: &Sender<EnsureObjectMessages>,
                ) {
                    flush_inline(&mut writer, &inline_content, &mut sha256_builder);

                    let finished = writer.finish().unwrap();

                    if let Some((context, expected)) = sha256_builder {
                        let final_sha = Into::<Sha256HashValue>::into(context.finalize());

                        if final_sha != expected {
                            println!(
                            "\x1b[31m===\nContent doesn't have expected SHA256 hash value!\nExpected: {}, final: {}\n===\n\x1b[0m",
                            hex::encode(expected),
                            hex::encode(final_sha)
                        );

                            // return;
                        }
                    }

                    if let Err(e) = cloned_sender.send(EnsureObjectMessages::Data(
                        SplitStreamWriterSenderData {
                            external_data: finished,
                            inline_content: vec![],
                            seq_num: 0,
                        },
                    )) {
                        println!("Failed to finish writer. Err: {e}");
                    };
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

                // if we get a seq that's larger then `last`, put it in `sequence`
                // put in the `sequence_index_map`, { sequence_number: index_into[sequence] }
                //
                // we get one that's equal to last, try to write all in sequence until we are out

                while let Ok(data) = write_chan_receiver.recv() {
                    match data {
                        WriterMessages::WriteData(recv_data) => {
                            let seq_num = recv_data.seq_num;

                            handle_received_message(recv_data, &mut heap);

                            if seq_num != last {
                                continue;
                            }

                            last = write_message(&mut heap, &mut writer, &mut sha256_builder, last);

                            if let Some(FinishMessage { total_msgs, .. }) = final_message {
                                if last >= total_msgs {
                                    println!(
                                        "Breaking {}. Last: {last}, total_msgs: {total_msgs}",
                                        hex::encode(sha256.unwrap())
                                    );
                                    break;
                                }
                            }
                        }

                        WriterMessages::Finish(final_msg) => {
                            if final_message.is_some() {
                                panic!("Received two finalize messages");
                            }

                            // write all pending messages
                            if !heap.is_empty() {
                                last = write_message(
                                    &mut heap,
                                    &mut writer,
                                    &mut sha256_builder,
                                    last,
                                );
                            }

                            let total_msgs = final_msg.total_msgs;

                            final_message = Some(final_msg);

                            if !heap.is_empty() {
                                // we still haven't received all the data, so can't finish right now
                                continue;
                            } else if last >= total_msgs {
                                break;
                            }
                        }
                    }
                }

                if let Some(FinishMessage {
                    data: inline_content,
                    ..
                }) = final_message
                {
                    handle_final_message(inline_content, writer, sha256_builder, &cloned_sender);
                }

                // wait for the final message
                // this should also be fine as mpsc::channel messages are always queued in case there
                // is no receiver receiving yet
                while let Ok(data) = write_chan_receiver.recv() {
                    match data {
                        WriterMessages::WriteData(data) => {
                            // let Some((.., ref sha256)) = sha256_builder else {
                            //     // bail!("Writer doesn't have sha256 enabled");
                            //     println!("\x1b[31mWriter doesn't have sha256 enabled\x1b[0m");
                            //     return;
                            // };

                            let stream_path = format!(
                                "streams/{}",
                                hex::encode(sha256.unwrap_or(/* TODO: Crash here... */ [0; 32]))
                            );

                            let object_path = Repository::format_object_path(&data.digest);
                            repository.ensure_symlink(&stream_path, &object_path);

                            // if let Some(name) = reference {
                            //     let reference_path = format!("streams/refs/{name}");
                            //     self.symlink(&reference_path, &stream_path)?;
                            // }

                            if let Err(e) =
                                done_chan_sender.send((sha256.unwrap_or([0; 32]), data.digest))
                            {
                                println!("Failed to send final digest with err: {e:?}");
                            }

                            break;
                        }

                        WriterMessages::Finish(..) => panic!("Received two finish requests"),
                    }
                }

                drop(cloned_sender);
                drop(done_chan_sender);
            }
        });

        SplitStreamWriter {
            repo,
            inline_content,
            // not used
            writer: Encoder::new(vec![], 0).unwrap(),
            object_sender,
            // not used
            sha256: sha256.map(|x| (Sha256::new(), x)),
        }
    }

    fn write_fragment(writer: &mut impl Write, size: usize, data: &[u8]) -> Result<()> {
        writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(writer.write_all(data)?)
    }

    /// flush any buffered inline data, taking new_value as the new value of the buffer
    fn flush_inline(&mut self, new_value: Vec<u8>) -> Result<()> {
        if !self.inline_content.is_empty() {
            SplitStreamWriter::write_fragment(
                &mut self.writer,
                self.inline_content.len(),
                &self.inline_content,
            )?;
            self.inline_content = new_value;
        }
        Ok(())
    }

    /// really, "add inline content to the buffer"
    /// you need to call .flush_inline() later
    pub fn write_inline(&mut self, data: &[u8]) {
        self.inline_content.extend(data);
    }

    pub fn write_external(&mut self, data: &[u8], padding: Vec<u8>, seq_num: usize) -> Result<()> {
        let inline_content = std::mem::replace(&mut self.inline_content, padding);

        if let Err(e) =
            self.object_sender
                .send(EnsureObjectMessages::Data(SplitStreamWriterSenderData {
                    external_data: data.to_vec(),
                    inline_content,
                    seq_num,
                }))
        {
            println!("Falied to send message. Err: {e:?}");
        }

        Ok(())
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
