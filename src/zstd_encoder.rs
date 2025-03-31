use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    io::{self, Write},
};

use sha2::{Digest, Sha256};

use anyhow::{bail, Result};
use zstd::Encoder;

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
    splitstream::{
        DigestMap, EnsureObjectMessages, FinishMessage, SplitStreamWriterSenderData,
        WriterMessages, WriterMessagesData,
    },
};

pub(crate) struct ZstdWriter {
    writer: zstd::Encoder<'static, Vec<u8>>,
    repository: Repository,
    pub(crate) sha256_builder: Option<(Sha256, Sha256HashValue)>,
    mode: WriterMode,
}

pub(crate) struct MultiThreadedState {
    last: usize,
    heap: BinaryHeap<Reverse<WriterMessagesData>>,
    final_sha: Option<Sha256HashValue>,
    final_message: Option<FinishMessage>,
    object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
    final_result_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
}

pub(crate) enum WriterMode {
    SingleThreaded,
    MultiThreaded(MultiThreadedState),
}

pub(crate) struct MultipleZstdWriters {
    writers: Vec<ZstdWriter>,
}

impl MultipleZstdWriters {
    pub fn new(
        sha256: Vec<Sha256HashValue>,
        repository: Repository,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
        final_result_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
    ) -> Self {
        Self {
            writers: sha256
                .iter()
                .map(|sha| {
                    ZstdWriter::new_threaded(
                        Some(*sha),
                        None,
                        repository.try_clone().unwrap(),
                        object_sender.clone(),
                        final_result_sender.clone(),
                    )
                })
                .collect(),
        }
    }

    pub fn recv_data(mut self, enc_chan_recvr: crossbeam::channel::Receiver<WriterMessages>) {
        // (layer num, writer idx)
        let mut layers_to_writers: Vec<(usize, usize)> = vec![];

        let mut finished_writers = 0;

        while let Ok(data) = enc_chan_recvr.recv() {
            let layer_num = match &data {
                WriterMessages::WriteData(d) => d.layer_num,
                WriterMessages::Finish(d) => d.layer_num,
            };

            let mut writer: Option<&mut ZstdWriter> = None;

            for (l_num, w_idx) in &layers_to_writers {
                if *l_num == layer_num {
                    writer = Some(&mut self.writers[*w_idx]);
                    break;
                }
            }

            if writer.is_none() {
                if self.writers.len() == layers_to_writers.len() {
                    panic!("Ran out of writers. layers_to_writers = {layers_to_writers:?}, layer_num: {layer_num:?}, total_writers: {}", self.writers.len());
                }

                layers_to_writers.push((
                    layer_num,
                    match layers_to_writers.last() {
                        Some((.., w_idx)) => {
                            writer = Some(&mut self.writers[w_idx + 1]);
                            w_idx + 1
                        }
                        None => {
                            writer = Some(&mut self.writers[0]);
                            0
                        }
                    },
                ));
            }

            if let Some(writer) = writer {
                if writer.handle_received_data(data) {
                    finished_writers += 1;
                }
            } else {
                panic!("Writer was none");
            }

            if finished_writers == self.writers.len() {
                break;
            }
        }
    }
}

impl ZstdWriter {
    pub fn new_threaded(
        sha256: Option<Sha256HashValue>,
        refs: Option<DigestMap>,
        repository: Repository,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
        final_result_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
    ) -> Self {
        Self {
            writer: ZstdWriter::get_writer(refs),
            repository,
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),

            mode: WriterMode::MultiThreaded(MultiThreadedState {
                final_sha: None,
                last: 0,
                heap: BinaryHeap::new(),
                final_message: None,
                object_sender,
                final_result_sender,
            }),
        }
    }

    pub fn new(
        sha256: Option<Sha256HashValue>,
        refs: Option<DigestMap>,
        repository: Repository,
    ) -> Self {
        Self {
            writer: ZstdWriter::get_writer(refs),
            repository,
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),
            mode: WriterMode::SingleThreaded,
        }
    }

    fn get_state(&self) -> &MultiThreadedState {
        let WriterMode::MultiThreaded(state) = &self.mode else {
            panic!("`get_state` called on a single threaded writer")
        };

        return state;
    }

    fn get_state_mut(&mut self) -> &mut MultiThreadedState {
        let WriterMode::MultiThreaded(state) = &mut self.mode else {
            panic!("`get_state_mut` called on a single threaded writer")
        };

        return state;
    }

    fn get_writer(refs: Option<DigestMap>) -> zstd::Encoder<'static, Vec<u8>> {
        let mut writer = zstd::Encoder::new(vec![], 0).unwrap();

        match refs {
            Some(DigestMap { map }) => {
                writer.write_all(&(map.len() as u64).to_le_bytes()).unwrap();

                for ref entry in map {
                    writer.write_all(&entry.body).unwrap();
                    writer.write_all(&entry.verity).unwrap();
                }
            }

            None => {
                writer.write_all(&0u64.to_le_bytes()).unwrap();
            }
        }

        return writer;
    }

    pub fn write_fragment(&mut self, size: usize, data: &[u8]) -> Result<()> {
        self.writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(self.writer.write_all(data)?)
    }

    pub fn flush_inline(&mut self, inline_content: &Vec<u8>) -> Result<()> {
        if inline_content.is_empty() {
            return Ok(());
        }

        if let Some((sha256, ..)) = &mut self.sha256_builder {
            sha256.update(&inline_content);
        }

        self.write_fragment(inline_content.len(), &inline_content)?;

        Ok(())
    }

    fn write_message(&mut self) {
        loop {
            // Gotta keep lifetime of the destructring inside the loop
            let state = self.get_state_mut();

            let Some(data) = state.heap.peek() else {
                break;
            };

            if data.0.seq_num != state.last {
                break;
            }

            let data = state.heap.pop().unwrap();
            state.last += 1;

            self.flush_inline(&data.0.inline_content);

            if let Some((sha256, ..)) = &mut self.sha256_builder {
                sha256.update(data.0.external_data);
            }

            if let Err(e) = self.write_fragment(0, &data.0.digest) {
                println!("write_fragment err while writing external content: {e:?}");
            }
        }

        let final_msg = self.get_state_mut().final_message.take();

        if let Some(final_msg) = final_msg {
            // Haven't received all the messages so we reset the final_message field
            if self.get_state().last < final_msg.total_msgs {
                self.get_state_mut().final_message = Some(final_msg);
                return;
            }

            let sha = self
                .handle_final_message(&final_msg.data, final_msg.layer_num)
                .unwrap();

            self.get_state_mut().final_sha = Some(sha);
        }
    }

    fn add_message_to_heap(&mut self, recv_data: WriterMessagesData) {
        self.get_state_mut().heap.push(Reverse(recv_data));
    }

    pub(crate) fn finalize_sha256_builder(&mut self) -> Result<Sha256HashValue> {
        let sha256_builder = std::mem::replace(&mut self.sha256_builder, None);

        let mut sha = Sha256HashValue::EMPTY;

        if let Some((context, expected)) = sha256_builder {
            let final_sha = Into::<Sha256HashValue>::into(context.finalize());

            if final_sha != expected {
                bail!(
                    "Content doesn't have expected SHA256 hash value!\nExpected: {}, final: {}",
                    hex::encode(expected),
                    hex::encode(final_sha)
                );
            }

            sha = final_sha;
        }

        return Ok(sha);
    }

    pub(crate) fn finish(self) -> io::Result<Vec<u8>> {
        self.writer.finish()
    }

    fn handle_final_message(
        &mut self,
        inline_content: &Vec<u8>,
        layer_num: usize,
    ) -> Result<Sha256HashValue> {
        self.flush_inline(&inline_content)?;

        let writer = std::mem::replace(&mut self.writer, Encoder::new(vec![], 0).unwrap());
        let finished = writer.finish()?;

        let sha = self.finalize_sha256_builder()?;

        if let Err(e) = self
            .get_state()
            .object_sender
            .send(EnsureObjectMessages::Data(SplitStreamWriterSenderData {
                external_data: finished,
                inline_content: vec![],
                seq_num: 0,
                layer_num,
            }))
        {
            println!("Failed to finish writer. Err: {e}");
        };

        Ok(sha)
    }

    // Cannot `take` ownership of self, as we'll need it later
    // returns whether finished or not
    fn handle_received_data(&mut self, data: WriterMessages) -> bool {
        match data {
            WriterMessages::WriteData(recv_data) => {
                if let Some(final_sha) = self.get_state().final_sha {
                    // We've already received the final messae
                    let stream_path = format!("streams/{}", hex::encode(final_sha));

                    let object_path = Repository::format_object_path(&recv_data.digest);
                    self.repository.ensure_symlink(&stream_path, &object_path);

                    // if let Some(name) = reference {
                    //     let reference_path = format!("streams/refs/{name}");
                    //     self.symlink(&reference_path, &stream_path)?;
                    // }

                    if let Err(e) = self
                        .get_state()
                        .final_result_sender
                        .send((final_sha, recv_data.digest))
                    {
                        println!("Failed to send final digest with err: {e:?}");
                    }

                    return true;
                }

                let seq_num = recv_data.seq_num;

                self.add_message_to_heap(recv_data);

                if seq_num != self.get_state().last {
                    return false;
                }

                self.write_message();
            }

            WriterMessages::Finish(final_msg) => {
                if self.get_state().final_message.is_some() {
                    panic!(
                        "Received two finalize messages for layer {}. Previous final message {:?}",
                        final_msg.layer_num,
                        self.get_state().final_message
                    );
                }

                // write all pending messages
                if !self.get_state().heap.is_empty() {
                    self.write_message();
                }

                let total_msgs = final_msg.total_msgs;
                let layer = final_msg.layer_num;

                if self.get_state().last >= total_msgs {
                    // We have received all the messages
                    // Finalize
                    let final_sha = self.handle_final_message(&final_msg.data, layer).unwrap();
                    self.get_state_mut().final_sha = Some(final_sha);
                } else {
                    // Haven't received all messages. Store the final message until we have
                    // received all
                    let state = self.get_state_mut();
                    state.final_message = Some(final_msg);
                }
            }
        }

        return false;
    }
}
