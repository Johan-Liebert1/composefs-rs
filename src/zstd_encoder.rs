use std::{cmp::Reverse, collections::BinaryHeap, io::Write};

use sha2::{Digest, Sha256};

use anyhow::Result;
use zstd::Encoder;

use crate::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository,
    splitstream::{
        DigestMap, EnsureObjectMessages, FinishMessage, SplitStreamWriter,
        SplitStreamWriterSenderData, WriterMessages, WriterMessagesData,
    },
};

pub(crate) struct ZstdWriter {
    writer: zstd::Encoder<'static, Vec<u8>>,
    repository: Repository,
    sha256_builder: Option<(Sha256, Sha256HashValue)>,

    last: usize,
    heap: BinaryHeap<Reverse<WriterMessagesData>>,
    final_sha: Option<Sha256HashValue>,
    final_message: Option<FinishMessage>,
    object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
    final_result_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
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
                    ZstdWriter::new(
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

        while let Ok(data) = enc_chan_recvr.recv() {
            let layer_num = match &data {
                WriterMessages::WriteData(d) => {
                    d.layer_num
                    // self.writers[d.layer_num % total_writers].handle_received_data(data)
                }
                WriterMessages::Finish(d) => {
                    d.layer_num
                    // self.writers[d.layer_num % total_writers].handle_received_data(data)
                }
            };

            let mut found = false;

            for (l_num, w_idx) in &layers_to_writers {
                if *l_num == layer_num {
                    self.writers[*w_idx].handle_received_data(data);
                    found = true;
                    break;
                }
            }

            if !found {
                if self.writers.len() == layers_to_writers.len() {
                    // ran out of writers
                    panic!("Ran out of writers. layers_to_writers = {layers_to_writers:?}, layer_num: {layer_num:?}, total_writers: {}", self.writers.len());
                }

                layers_to_writers.push((
                    layer_num,
                    match layers_to_writers.last() {
                        Some((.., w_idx)) => w_idx + 1,
                        None => 0,
                    },
                ));
            }
        }
    }
}

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

    if let Err(e) = SplitStreamWriter::write_fragment(writer, inline_content.len(), &inline_content)
    {
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
        if let Err(e) = SplitStreamWriter::write_fragment(writer, 0, &data.0.digest) {
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
    inline_content: &Vec<u8>,
    mut writer: zstd::Encoder<'static, Vec<u8>>,
    mut sha256_builder: Option<(Sha256, Sha256HashValue)>,
    cloned_sender: &crossbeam::channel::Sender<EnsureObjectMessages>,
) -> Result<Sha256HashValue> {
    flush_inline(&mut writer, &inline_content, &mut sha256_builder);

    let mut sha = Sha256HashValue::EMPTY;

    if let Some((context, expected)) = sha256_builder {
        let final_sha = Into::<Sha256HashValue>::into(context.finalize());

        if final_sha != expected {
            println!(
                "\x1b[31m===\nContent doesn't have expected SHA256 hash value!\nExpected: {}, final: {}\n===\n\x1b[0m",
                hex::encode(expected),
                hex::encode(final_sha)
            );

            // TODO: Return err
            todo!()
        }

        sha = final_sha;
    }

    let finished = writer.finish().unwrap();

    if let Err(e) = cloned_sender.send(EnsureObjectMessages::Data(SplitStreamWriterSenderData {
        external_data: finished,
        inline_content: vec![],
        seq_num: 0,
        layer_num: todo!(),
    })) {
        println!("Failed to finish writer. Err: {e}");
    };

    Ok(sha)
}

impl ZstdWriter {
    pub fn new(
        sha256: Option<Sha256HashValue>,
        refs: Option<DigestMap>,
        repository: Repository,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
        final_result_sender: std::sync::mpsc::Sender<(Sha256HashValue, Sha256HashValue)>,
    ) -> Self {
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

        Self {
            writer,
            repository,
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),
            final_sha: None,
            last: 0,
            heap: BinaryHeap::new(),
            final_message: None,
            object_sender,
            final_result_sender,
        }
    }

    // Cannot `take` ownership of self, as we'll need it later
    fn handle_received_data(&mut self, data: WriterMessages) {
        match data {
            WriterMessages::WriteData(recv_data) => {
                if let Some(final_sha) = self.final_sha {
                    // We've already received the final messae
                    let stream_path = format!("streams/{}", hex::encode(final_sha));

                    let object_path = Repository::format_object_path(&recv_data.digest);
                    self.repository.ensure_symlink(&stream_path, &object_path);

                    // if let Some(name) = reference {
                    //     let reference_path = format!("streams/refs/{name}");
                    //     self.symlink(&reference_path, &stream_path)?;
                    // }

                    if let Err(e) = self.final_result_sender.send((final_sha, recv_data.digest)) {
                        println!("Failed to send final digest with err: {e:?}");
                    }

                    return;
                }

                let seq_num = recv_data.seq_num;

                handle_received_message(recv_data, &mut self.heap);

                if seq_num != self.last {
                    return;
                }

                self.last = write_message(
                    &mut self.heap,
                    &mut self.writer,
                    &mut self.sha256_builder,
                    self.last,
                );

                if let Some(FinishMessage {
                    total_msgs,
                    data: inline_content,
                    ..
                }) = &self.final_message
                {
                    if self.last >= *total_msgs {
                        let final_sha = handle_final_message(
                            inline_content,
                            std::mem::replace(&mut self.writer, Encoder::new(vec![], 0).unwrap()),
                            std::mem::replace(&mut self.sha256_builder, None),
                            &self.object_sender,
                        )
                        .unwrap();
                        self.final_sha = Some(final_sha);
                        return;
                    }
                }
            }

            WriterMessages::Finish(final_msg) => {
                if self.final_message.is_some() {
                    panic!("Received two finalize messages. {final_msg:?}");
                }

                println!("Received final message. {final_msg:?}");

                // write all pending messages
                if !self.heap.is_empty() {
                    self.last = write_message(
                        &mut self.heap,
                        &mut self.writer,
                        &mut self.sha256_builder,
                        self.last,
                    );
                }

                let total_msgs = final_msg.total_msgs;

                self.final_message = Some(final_msg);

                if !self.heap.is_empty() {
                    // we still haven't received all the data, so can't finish right now
                    return;
                } else if self.last >= total_msgs {
                    let final_sha = handle_final_message(
                        &self.final_message.take().unwrap().data,
                        std::mem::replace(&mut self.writer, Encoder::new(vec![], 0).unwrap()),
                        std::mem::replace(&mut self.sha256_builder, None),
                        &self.object_sender,
                    )
                    .unwrap();
                    self.final_sha = Some(final_sha);
                    return;
                }
            }
        }
    }

    pub fn recv_data(mut self, enc_chan_recvr: crossbeam::channel::Receiver<WriterMessages>) {
        while let Ok(data) = enc_chan_recvr.recv() {
            match data {
                WriterMessages::WriteData(recv_data) => {
                    let seq_num = recv_data.seq_num;

                    handle_received_message(recv_data, &mut self.heap);

                    if seq_num != self.last {
                        continue;
                    }

                    self.last = write_message(
                        &mut self.heap,
                        &mut self.writer,
                        &mut self.sha256_builder,
                        self.last,
                    );

                    if let Some(FinishMessage { total_msgs, .. }) = self.final_message {
                        if self.last >= total_msgs {
                            break;
                        }
                    }
                }

                WriterMessages::Finish(final_msg) => {
                    if self.final_message.is_some() {
                        panic!("Received two finalize messages");
                    }

                    // write all pending messages
                    if !self.heap.is_empty() {
                        self.last = write_message(
                            &mut self.heap,
                            &mut self.writer,
                            &mut self.sha256_builder,
                            self.last,
                        );
                    }

                    let total_msgs = final_msg.total_msgs;

                    self.final_message = Some(final_msg);

                    if !self.heap.is_empty() {
                        // we still haven't received all the data, so can't finish right now
                        continue;
                    } else if self.last >= total_msgs {
                        break;
                    }
                }
            }
        }

        let Some(FinishMessage {
            data: inline_content,
            ..
        }) = self.final_message
        else {
            // TODO: Better errors
            panic!("bruh")
        };

        let final_sha = handle_final_message(
            &inline_content,
            self.writer,
            self.sha256_builder,
            &self.object_sender,
        )
        .unwrap();

        // wait for the final message
        // this should also be fine as mpsc::channel messages are always queued in case there
        // is no receiver receiving yet
        while let Ok(data) = enc_chan_recvr.recv() {
            match data {
                WriterMessages::WriteData(data) => {
                    let stream_path = format!("streams/{}", hex::encode(final_sha));

                    let object_path = Repository::format_object_path(&data.digest);
                    self.repository.ensure_symlink(&stream_path, &object_path);

                    // if let Some(name) = reference {
                    //     let reference_path = format!("streams/refs/{name}");
                    //     self.symlink(&reference_path, &stream_path)?;
                    // }

                    if let Err(e) = self.final_result_sender.send((final_sha, data.digest)) {
                        println!("Failed to send final digest with err: {e:?}");
                    }

                    break;
                }

                WriterMessages::Finish(..) => panic!("Received two finish requests"),
            }
        }
    }
}
