// Copyright (c) 2023 Yuki Kishimoto
// Distributed under the MIT software license

//! Rust implementation of the negentropy set-reconciliation protocol.

#![warn(missing_docs)]
#![cfg_attr(bench, feature(test))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(bench)]
extern crate test;

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use std::collections::HashSet;
use std::rc::Rc;

mod error;
mod encoding;
mod bytes;
mod hex;
mod sha256;
mod types;
mod storage;

pub use self::bytes::Bytes;
pub use self::error::Error;
pub use self::storage::{NegentropyStorageBase};

use self::types::{MAX_U64, PROTOCOL_VERSION, FINGERPRINT_SIZE, BUCKETS, DOUBLE_BUCKETS, Mode, Item, Bound};
use self::encoding::{get_bytes, decode_mode, decode_var_int, encode_mode, encode_var_int};



/// Negentropy
#[derive(Debug, Clone)]
pub struct Negentropy {
    storage: Rc<dyn NegentropyStorageBase>,
    frame_size_limit: Option<u64>,

    is_initiator: bool,

    last_timestamp_in: u64,
    last_timestamp_out: u64,
}

impl Negentropy {
    /// Create new [`Negentropy`] instance
    pub fn new(storage: Rc<dyn NegentropyStorageBase>, frame_size_limit: Option<u64>) -> Result<Self, Error> {
        if let Some(frame_size_limit) = frame_size_limit {
            if frame_size_limit > 0 && frame_size_limit < 4096 {
                return Err(Error::FrameSizeLimitTooSmall);
            }
        }

        Ok(Self {
            storage: storage,
            frame_size_limit: frame_size_limit,

            is_initiator: false,

            last_timestamp_in: 0,
            last_timestamp_out: 0,
        })
    }

    /// Initiate reconciliation set
    pub fn initiate(&mut self) -> Result<Bytes, Error> {
        if self.is_initiator {
            return Err(Error::AlreadyBuiltInitialMessage);
        }
        self.is_initiator = true;

        let mut output: Vec<u8> = Vec::new();
        output.push(PROTOCOL_VERSION as u8);

        output.extend(self.split_range(0, self.storage.size()?, Bound::new(), Bound::with_timestamp(MAX_U64))?);

        Ok(Bytes::from(output))
    }

    /// Reconcile (server method)
    pub fn reconcile(&mut self, query: &Bytes) -> Result<Bytes, Error> {
        if self.is_initiator {
            return Err(Error::Initiator);
        }

        let mut query: &[u8] = query.as_ref();

        let output = self.reconcile_aux(query, &mut Vec::new(), &mut Vec::new())?;

        Ok(output)
    }

    /// Reconcile (client method)
    pub fn reconcile_with_ids(
        &mut self,
        query: &Bytes,
        have_ids: &mut Vec<Bytes>,
        need_ids: &mut Vec<Bytes>,
    ) -> Result<Option<Bytes>, Error> {
        if !self.is_initiator {
            return Err(Error::NonInitiator);
        }

        let query: &[u8] = query.as_ref();

        let output = self.reconcile_aux(query, have_ids, need_ids)?;
        if output.len() == 1 {
            return Ok(None);
        }

        Ok(Some(Bytes::from(output)))
    }

    fn reconcile_aux(
        &mut self,
        mut query: &[u8],
        have_ids: &mut Vec<Bytes>,
        need_ids: &mut Vec<Bytes>,
    ) -> Result<Bytes, Error> {
        self.last_timestamp_in = 0;
        self.last_timestamp_out = 0;

        let mut full_output: Vec<u8> = Vec::new();
        full_output.push(PROTOCOL_VERSION as u8);

        let protocol_version = get_bytes(&mut query, 1)?[0] as u64;

        if !(0x60..=0x6F).contains(&protocol_version) {
            return Err(Error::InvalidProtocolVersion);
        }

        if protocol_version != PROTOCOL_VERSION {
            if self.is_initiator {
                return Err(Error::UnsupportedProtocolVersion);
            } else {
                return Ok(Bytes::from(full_output));
            }
        }

        let storage_size = self.storage.size()?;
        let mut prev_bound: Bound = Bound::new();
        let mut prev_index: usize = 0;
        let skip: bool = false;

        while !query.is_empty() {
            let mut o: Vec<u8> = Vec::new();

            let do_skip = || {
                if skip {
                    skip = false;
                    o.extend(self.encode_bound(prev_bound));
                    o.extend(encode_mode(Mode::Skip));
                }
            };

            let curr_bound: Item = self.decode_bound(&mut query, &mut self.last_timestamp_in)?;
            let mode: Mode = decode_mode(&mut query)?;

            let lower: usize = prev_index;
            let upper: usize = self.storage.find_lower_bound(prev_index, storage_size, &curr_bound)?;

            match mode {
                Mode::Skip => {
                    skip = true;
                },
                Mode::Fingerprint => {
                    let their_fingerprint: Vec<u8> = get_bytes(&mut query, FINGERPRINT_SIZE)?;
                    let our_fingerprint: Vec<u8> = self.storage.fingerprint(lower, upper)?;

                    if their_fingerprint != our_fingerprint {
                        do_skip();
                        o.extend(self.split_range(lower, upper, prev_bound, curr_bound)?);
                    } else {
                        skip = true;
                    }
                }
                Mode::IdList => {
                    let num_ids: u64 = decode_var_int(&mut query)?;

                    #[cfg(feature = "std")]
                    let mut their_elems: HashSet<Vec<u8>> =
                        HashSet::with_capacity(num_ids as usize);
                    #[cfg(not(feature = "std"))]
                    let mut their_elems: BTreeSet<Vec<u8>> = BTreeSet::new();

                    for _ in 0..num_ids {
                        let e: Vec<u8> = get_bytes(&mut query, self.id_size)?;
                        their_elems.insert(e);
                    }

                    self.storage.iterate(lower, upper, |item, _| {
                        let k = item.id;
                        if !their_elems.contains(k) {
                            if self.is_initiator {
                                have_ids.push(Bytes::from(k));
                            }
                        } else {
                            their_elems.remove(k);
                        }

                        return true;
                    })?;

                    if self.is_initiator {
                        skip = true;

                        for k in their_elems.into_iter() {
                            need_ids.push(Bytes::from(k));
                        }
                    } else {
                        do_skip();

                        let mut response_ids: Vec<u8> = Vec::new();
                        let mut num_response_ids: usize = 0;
                        let mut end_bound = curr_bound;

                        self.storage.iterate(lower, upper, |item, index| {
                            if self.frame_size_limit != 0 && full_output.len() + response_ids.len() > self.frame_size_limit + 200 {
                                end_bound = Bound::new();
                                upper = index; // shrink upper so that remaining range gets correct fingerprint
                                return false;
                            }

                            response_ids.extend(item.id);
                            num_response_ids = num_response_ids + 1;
                            return true;
                        })?;

                        o.extend(self.encode_bound(end_bound));
                        o.extend(encode_mode(Mode::IdList));
                        o.extend(encode_var_int(num_response_ids));
                        o.extend(response_ids);

                        full_output.extend(o);
                        o.clear();
                    }
                }
            }

            if self.frame_size_limit != 0 && full_output.len() + o.len() > self.frame_size_limit + 200 {
                // frameSizeLimit exceeded: Stop range processing and return a fingerprint for the remaining range
                let remaining_fingerprint = self.storage.fingerprint(upper, storage_size)?;

                full_output.extend(self.encode_bound(Bound::with_timestamp(MAX_U64)));
                full_output.extend(encode_mode(Mode::Fingerprint));
                full_output.extend(remaining_fingerprint.buf);
            } else {
                full_output.extend(o);
            }

            prev_index = upper;
            prev_bound = curr_bound;
        }

        Ok(Bytes::from(full_output))
    }

    fn split_range(
        &self,
        lower: usize,
        upper: usize,
        lower_bound: Bound,
        upper_bound: Bound,
    ) -> Result<Vec<u8>, Error> {
        let num_elems: usize = upper - lower;
        let mut o: Vec<u8> = Vec::with_capacity(10 + 10 + num_elems);

        if num_elems < DOUBLE_BUCKETS {
            o.extend(self.encode_bound(upper_bound));
            o.extend(encode_mode(Mode::IdList));

            o.extend(encode_var_int(num_elems as u64));
            self.storage.iterate(lower, upper, |item| {
                o.extend(item.id);
                return true;
            })?;
        } else {
            let items_per_bucket: usize = num_elems / BUCKETS;
            let buckets_with_extra: usize = num_elems % BUCKETS;
            let mut curr: usize = lower;
            let mut prev_bound: Bound = Bound::from_item(self.storage.get_item(curr)?);

            for i in 0..BUCKETS {
                let bucket_size: usize =
                    items_per_bucket + (if i < buckets_with_extra { 1 } else { 0 });
                let our_fingerprint = self.storage.fingerprint(curr, curr + bucket_size)?;
                curr += bucket_size;

                let next_prev_bound = if curr == upper {
                    upper_bound
                } else {
                    self.get_minimal_bound(&self.storage.get_item(curr - 1)?, &self.storage.get_item(curr)?)?
                };

                o.extend(self.encode_bound(next_prev_bound));
                o.extend(encode_mode(Mode::Fingerprint));
                o.extend(our_fingerprint);

                prev_bound = next_prev_bound;
            }
        }

        Ok(Bytes::from(o))
    }



    fn decode_timestamp_in(
        &self,
        encoded: &mut &[u8],
        last_timestamp_in: &mut u64,
    ) -> Result<u64, Error> {
        let timestamp: u64 = decode_var_int(encoded)?;
        let mut timestamp = if timestamp == 0 {
            MAX_U64
        } else {
            timestamp - 1
        };
        timestamp = timestamp.saturating_add(*last_timestamp_in);
        *last_timestamp_in = timestamp;
        Ok(timestamp)
    }

    fn decode_bound(
        &self,
        encoded: &mut &[u8],
        last_timestamp_in: &mut u64,
    ) -> Result<Item, Error> {
        let timestamp = self.decode_timestamp_in(encoded, last_timestamp_in)?;
        let len = decode_var_int(encoded)?;
        let id = get_bytes(encoded, len as usize)?;
        Item::with_timestamp_and_id(timestamp, id)
    }


    fn encode_timestamp_out(&self, timestamp: u64, last_timestamp_out: &mut u64) -> Vec<u8> {
        if timestamp == MAX_U64 {
            *last_timestamp_out = MAX_U64;
            return encode_var_int(0);
        }

        let temp: u64 = timestamp;
        let timestamp: u64 = timestamp.saturating_sub(*last_timestamp_out);
        *last_timestamp_out = temp;
        encode_var_int(timestamp.saturating_add(1))
    }

    fn encode_bound(&self, bound: &Item, last_timestamp_out: &mut u64) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        output.extend(self.encode_timestamp_out(bound.timestamp, last_timestamp_out));
        output.extend(encode_var_int(bound.id_size() as u64));
        output.extend(bound.get_id());
        output
    }

    fn get_minimal_bound(&self, prev: &Item, curr: &Item) -> Result<Item, Error> {
        if curr.timestamp != prev.timestamp {
            Ok(Item::with_timestamp(curr.timestamp))
        } else {
            let mut shared_prefix_bytes: usize = 0;
            for i in 0..prev.id_size().min(curr.id_size()) {
                if curr.id[i] != prev.id[i] {
                    break;
                }
                shared_prefix_bytes += 1;
            }
            Item::with_timestamp_and_id(curr.timestamp, &curr.id[..shared_prefix_bytes + 1])
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_reconciliation_set() {
        // Client
        let mut client = Negentropy::new(16, None).unwrap();
        client
            .add_item(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            )
            .unwrap();
        client
            .add_item(
                1,
                Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            )
            .unwrap();
        client.seal().unwrap();
        let init_output = client.initiate().unwrap();

        // Relay
        let mut relay = Negentropy::new(16, None).unwrap();
        relay
            .add_item(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            )
            .unwrap();
        relay
            .add_item(
                2,
                Bytes::from_hex("cccccccccccccccccccccccccccccccc").unwrap(),
            )
            .unwrap();
        relay
            .add_item(
                3,
                Bytes::from_hex("11111111111111111111111111111111").unwrap(),
            )
            .unwrap();
        relay
            .add_item(
                5,
                Bytes::from_hex("22222222222222222222222222222222").unwrap(),
            )
            .unwrap();
        relay
            .add_item(
                10,
                Bytes::from_hex("33333333333333333333333333333333").unwrap(),
            )
            .unwrap();
        relay.seal().unwrap();
        let reconcile_output = relay.reconcile(&init_output).unwrap();

        // Client
        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let reconcile_output_with_ids = client
            .reconcile_with_ids(&reconcile_output, &mut have_ids, &mut need_ids)
            .unwrap();

        // Check reconcile with IDs output
        assert!(reconcile_output_with_ids.is_none());

        // Check have IDs
        assert!(have_ids.contains(&Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()));

        // Check need IDs
        #[cfg(feature = "std")]
        need_ids.sort();
        assert_eq!(
            need_ids,
            vec![
                Bytes::from_hex("11111111111111111111111111111111").unwrap(),
                Bytes::from_hex("22222222222222222222222222222222").unwrap(),
                Bytes::from_hex("33333333333333333333333333333333").unwrap(),
                Bytes::from_hex("cccccccccccccccccccccccccccccccc").unwrap(),
            ]
        )
    }

    #[test]
    fn test_invalid_id_size() {
        assert_eq!(Negentropy::new(33, None).unwrap_err(), Error::InvalidIdSize);

        let mut client = Negentropy::new(16, None).unwrap();
        assert_eq!(
            client
                .add_item(0, Bytes::from_hex("abcdef").unwrap())
                .unwrap_err(),
            Error::IdSizeNotMatch
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::{Bytes, Negentropy};

    const ID_SIZE: usize = 16;
    const FRAME_SIZE_LIMIT: Option<u64> = None;
    const ITEMS_LEN: usize = 100_000;

    #[bench]
    pub fn add_item(bh: &mut Bencher) {
        let mut client = Negentropy::new(ID_SIZE, FRAME_SIZE_LIMIT).unwrap();
        bh.iter(|| {
            black_box(client.add_item(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            ))
            .unwrap();
        });
    }

    #[bench]
    pub fn final_reconciliation_100_000_items(bh: &mut Bencher) {
        // Client
        let mut client = Negentropy::new(ID_SIZE, FRAME_SIZE_LIMIT).unwrap();
        for (index, item) in generate_combinations("abc", 32, 2).into_iter().enumerate() {
            client
                .add_item(index as u64, Bytes::from_hex(item).unwrap())
                .unwrap();
        }
        client.seal().unwrap();
        let init_output = client.initiate().unwrap();

        let mut relay = Negentropy::new(ID_SIZE, FRAME_SIZE_LIMIT).unwrap();
        for (index, item) in generate_combinations("abc", 32, ITEMS_LEN)
            .into_iter()
            .enumerate()
        {
            relay
                .add_item(index as u64, Bytes::from_hex(item).unwrap())
                .unwrap();
        }
        relay.seal().unwrap();
        let reconcile_output = relay.reconcile(&init_output).unwrap();

        bh.iter(|| {
            let mut have_ids = Vec::new();
            let mut need_ids = Vec::new();
            black_box(client.reconcile_with_ids(&reconcile_output, &mut have_ids, &mut need_ids))
                .unwrap();
        });
    }

    fn generate_combinations(characters: &str, length: usize, max: usize) -> Vec<String> {
        let mut combinations = Vec::new();
        let mut current = String::new();
        generate_combinations_recursive(
            &mut combinations,
            &mut current,
            characters,
            length,
            0,
            max,
        );
        combinations
    }

    fn generate_combinations_recursive(
        combinations: &mut Vec<String>,
        current: &mut String,
        characters: &str,
        length: usize,
        index: usize,
        max: usize,
    ) {
        if length == 0 {
            combinations.push(current.clone());
            return;
        }

        for char in characters.chars() {
            if combinations.len() < max {
                current.push(char);
                generate_combinations_recursive(
                    combinations,
                    current,
                    characters,
                    length - 1,
                    index + 1,
                    max,
                );
                current.pop();
            } else {
                return;
            }
        }
    }
}
