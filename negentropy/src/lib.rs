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
#[cfg(feature = "std")]
use std::convert::TryFrom;

use std::collections::HashSet;

mod error;
mod encoding;
mod bytes;
mod hex;
mod sha256;
mod types;

/// Module that contains the various storage implementations
pub mod storage;

pub use self::bytes::Bytes;
pub use self::error::Error;
pub use self::storage::{NegentropyStorageBase};

use self::types::{PROTOCOL_VERSION, ID_SIZE, FINGERPRINT_SIZE, Mode, Item, Bound};
use self::encoding::{get_bytes, decode_var_int, encode_var_int};


const MAX_U64: u64 = u64::MAX;
const BUCKETS: usize = 16;
const DOUBLE_BUCKETS: usize = BUCKETS * 2;


/// Negentropy
pub struct Negentropy<'a, T> {
    storage: &'a mut T,
    frame_size_limit: u64,

    /// If this instance has been used to create an initial message
    pub is_initiator: bool,

    last_timestamp_in: u64,
    last_timestamp_out: u64,
}

impl<'a, T: NegentropyStorageBase> Negentropy<'a, T> {
    /// Create new [`Negentropy`] instance
    pub fn new(storage: &'a mut T, frame_size_limit: u64) -> Result<Self, Error> {
        if frame_size_limit != 0 && frame_size_limit < 4096 {
            return Err(Error::FrameSizeLimitTooSmall);
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

        output.extend(self.split_range(0, self.storage.size()?, Bound::with_timestamp(MAX_U64))?);

        Ok(Bytes::from(output))
    }

    /// Set Initiator: For resuming initiation flow with a new instance
    pub fn setInitiator(&mut self) {
        self.is_initiator = true;
    }

    /// Reconcile (server method)
    pub fn reconcile(&mut self, query: &Bytes) -> Result<Bytes, Error> {
        if self.is_initiator {
            return Err(Error::Initiator);
        }

        let query: &[u8] = query.as_ref();

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
        let mut skip: bool = false;

        while !query.is_empty() {
            let mut o: Vec<u8> = Vec::new();

            let curr_bound: Bound = self.decode_bound(&mut query)?;
            let mode: Mode = self.decode_mode(&mut query)?;

            let lower: usize = prev_index;
            let mut upper: usize = self.storage.find_lower_bound(prev_index, storage_size, &curr_bound);

            match mode {
                Mode::Skip => {
                    skip = true;
                },
                Mode::Fingerprint => {
                    let their_fingerprint: Vec<u8> = get_bytes(&mut query, FINGERPRINT_SIZE)?;
                    let our_fingerprint: Vec<u8> = self.storage.fingerprint(lower, upper)?.vec();

                    if their_fingerprint != our_fingerprint {
                        // do_skip
                        if skip {
                            skip = false;
                            o.extend(self.encode_bound(&prev_bound));
                            o.extend(self.encode_mode(Mode::Skip));
                        }

                        o.extend(self.split_range(lower, upper, curr_bound)?);
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
                        let e: Vec<u8> = get_bytes(&mut query, ID_SIZE)?;
                        their_elems.insert(e);
                    }

                    self.storage.iterate(lower, upper, &mut |item: Item, _| {
                        let k = item.id.to_vec();
                        if !their_elems.contains(&k) {
                            if self.is_initiator {
                                have_ids.push(Bytes::from(k));
                            }
                        } else {
                            their_elems.remove(&k);
                        }

                        true
                    })?;

                    if self.is_initiator {
                        skip = true;

                        for k in their_elems.into_iter() {
                            need_ids.push(Bytes::from(k));
                        }
                    } else {
                        // do_skip
                        if skip {
                            skip = false;
                            o.extend(self.encode_bound(&prev_bound));
                            o.extend(self.encode_mode(Mode::Skip));
                        }

                        let mut response_ids: Vec<u8> = Vec::new();
                        let mut num_response_ids: usize = 0;
                        let mut end_bound = curr_bound;

                        self.storage.iterate(lower, upper, &mut |item: Item, index| {
                            if self.exceeded_frame_size_limit(full_output.len() + response_ids.len()) {
                                end_bound = Bound::from_item(&item);
                                upper = index; // shrink upper so that remaining range gets correct fingerprint
                                return false;
                            }

                            response_ids.extend(&item.id);
                            num_response_ids = num_response_ids + 1;
                            true
                        })?;

                        o.extend(self.encode_bound(&end_bound));
                        o.extend(self.encode_mode(Mode::IdList));
                        o.extend(encode_var_int(num_response_ids as u64));
                        o.extend(response_ids);

                        full_output.extend(&o);
                        o.clear();
                    }
                }
            }

            if self.exceeded_frame_size_limit(full_output.len() + o.len()) {
                // frameSizeLimit exceeded: Stop range processing and return a fingerprint for the remaining range
                let remaining_fingerprint = self.storage.fingerprint(upper, storage_size)?;

                full_output.extend(self.encode_bound(&Bound::with_timestamp(MAX_U64)));
                full_output.extend(self.encode_mode(Mode::Fingerprint));
                full_output.extend(&remaining_fingerprint.buf);
                break;
            } else {
                full_output.extend(o);
            }

            prev_index = upper;
            prev_bound = curr_bound;
        }

        Ok(Bytes::from(full_output))
    }

    fn split_range(
        &mut self,
        lower: usize,
        upper: usize,
        upper_bound: Bound,
    ) -> Result<Vec<u8>, Error> {
        let num_elems: usize = upper - lower;
        let mut o: Vec<u8> = Vec::with_capacity(10 + 10 + num_elems);

        if num_elems < DOUBLE_BUCKETS {
            o.extend(self.encode_bound(&upper_bound));
            o.extend(self.encode_mode(Mode::IdList));

            o.extend(encode_var_int(num_elems as u64));
            self.storage.iterate(lower, upper, &mut |item: Item, _| {
                o.extend(&item.id);
                true
            })?;
        } else {
            let items_per_bucket: usize = num_elems / BUCKETS;
            let buckets_with_extra: usize = num_elems % BUCKETS;
            let mut curr: usize = lower;

            for i in 0..BUCKETS {
                let bucket_size: usize =
                    items_per_bucket + (if i < buckets_with_extra { 1 } else { 0 });
                let our_fingerprint = self.storage.fingerprint(curr, curr + bucket_size)?;
                curr += bucket_size;

                let next_bound = if curr == upper {
                    upper_bound
                } else {
                    self.get_minimal_bound(&self.storage.get_item(curr - 1)?, &self.storage.get_item(curr)?)?
                };

                o.extend(self.encode_bound(&next_bound));
                o.extend(self.encode_mode(Mode::Fingerprint));
                o.extend(our_fingerprint.vec());
            }
        }

        Ok(o)
    }


    fn exceeded_frame_size_limit(&self, n: usize) -> bool {
        self.frame_size_limit != 0 && n > (self.frame_size_limit as usize) - 200
    }


    // Decoding

    fn decode_mode(&self, encoded: &mut &[u8]) -> Result<Mode, Error> {
        let mode = decode_var_int(encoded)?;
        Mode::try_from(mode)
    }

    fn decode_timestamp_in(
        &mut self,
        encoded: &mut &[u8],
    ) -> Result<u64, Error> {
        let timestamp: u64 = decode_var_int(encoded)?;
        let mut timestamp = if timestamp == 0 {
            MAX_U64
        } else {
            timestamp - 1
        };
        timestamp = timestamp.saturating_add(self.last_timestamp_in);
        self.last_timestamp_in = timestamp;
        Ok(timestamp)
    }

    fn decode_bound(
        &mut self,
        encoded: &mut &[u8],
    ) -> Result<Bound, Error> {
        let timestamp = self.decode_timestamp_in(encoded)?;
        let len = decode_var_int(encoded)?;
        let id = get_bytes(encoded, len as usize)?;
        Ok(Bound::with_timestamp_and_id(timestamp, id)?)
    }


    // Encoding

    fn encode_mode(&self, mode: Mode) -> Vec<u8> {
        encode_var_int(mode.as_u64())
    }

    fn encode_timestamp_out(&mut self, timestamp: u64) -> Vec<u8> {
        if timestamp == MAX_U64 {
            self.last_timestamp_out = MAX_U64;
            return encode_var_int(0);
        }

        let temp: u64 = timestamp;
        let timestamp: u64 = timestamp.saturating_sub(self.last_timestamp_out);
        self.last_timestamp_out = temp;
        encode_var_int(timestamp.saturating_add(1))
    }

    fn encode_bound(&mut self, bound: &Bound) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();

        output.extend(self.encode_timestamp_out(bound.item.timestamp));
        output.extend(encode_var_int(bound.id_len as u64));

        let mut bound_slice = bound.item.id.to_vec();
        bound_slice.resize(bound.id_len, 0);
        output.extend(bound_slice);

        output
    }

    fn get_minimal_bound(&self, prev: &Item, curr: &Item) -> Result<Bound, Error> {
        if curr.timestamp != prev.timestamp {
            Ok(Bound::with_timestamp(curr.timestamp))
        } else {
            let mut shared_prefix_bytes: usize = 0;
            let curr_key = curr.id;
            let prev_key = prev.id;

            for i in 0..ID_SIZE {
                if curr_key[i] != prev_key[i] {
                    break;
                }
                shared_prefix_bytes += 1;
            }
            Ok(Bound::with_timestamp_and_id(curr.timestamp, &curr_key[..shared_prefix_bytes + 1])?)
        }
    }
}

#[cfg(test)]
mod tests {
    use self::storage::{NegentropyStorageVector};
    use alloc::vec;

    use super::*;

    #[test]
    fn test_reconciliation_set() {
        // Client
        let mut storage_client = NegentropyStorageVector::new().unwrap();
        storage_client
            .insert(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            )
            .unwrap();
        storage_client
            .insert(
                1,
                Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            )
            .unwrap();
        storage_client.seal().unwrap();

        let mut client = Negentropy::new(&mut storage_client, 0).unwrap();
        let init_output = client.initiate().unwrap();

        // Relay
        let mut storage_relay = NegentropyStorageVector::new().unwrap();
        storage_relay
            .insert(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            )
            .unwrap();
        storage_relay
            .insert(
                2,
                Bytes::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap(),
            )
            .unwrap();
        storage_relay
            .insert(
                3,
                Bytes::from_hex("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
            )
            .unwrap();
        storage_relay
            .insert(
                5,
                Bytes::from_hex("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
            )
            .unwrap();
        storage_relay
            .insert(
                10,
                Bytes::from_hex("3333333333333333333333333333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap();
        storage_relay.seal().unwrap();
        let mut relay = Negentropy::new(&mut storage_relay, 0).unwrap();
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
        assert!(have_ids.contains(&Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap()));

        // Check need IDs
        #[cfg(feature = "std")]
        need_ids.sort();
        assert_eq!(
            need_ids,
            vec![
                Bytes::from_hex("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
                Bytes::from_hex("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
                Bytes::from_hex("3333333333333333333333333333333333333333333333333333333333333333").unwrap(),
                Bytes::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap(),
            ]
        )
    }

    #[test]
    fn test_invalid_id_size() {
        let mut storage_client = NegentropyStorageVector::new().unwrap();
        assert_eq!(
            storage_client
                .insert(0, Bytes::from_hex("abcdef").unwrap())
                .unwrap_err(),
            Error::IdSizeNotMatch
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::storage::{NegentropyStorageVector};
    use super::{Bytes, Negentropy};

    const ITEMS_LEN: usize = 100_000;

    #[bench]
    pub fn insert(bh: &mut Bencher) {
        let mut storage_client = NegentropyStorageVector::new().unwrap();
        bh.iter(|| {
            black_box(storage_client.insert(
                0,
                Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            ))
            .unwrap();
        });
    }

    #[bench]
    pub fn final_reconciliation_100_000_items(bh: &mut Bencher) {
        // Client
        let mut storage_client = NegentropyStorageVector::new().unwrap();
        for (index, item) in generate_combinations("abc", 32, 2).into_iter().enumerate() {
            storage_client
                .insert(index as u64, Bytes::from_hex(item).unwrap())
                .unwrap();
        }
        storage_client.seal().unwrap();
        let mut client = Negentropy::new(&mut storage_client, 0).unwrap();
        let init_output = client.initiate().unwrap();

        let mut storage_relay = NegentropyStorageVector::new().unwrap();
        for (index, item) in generate_combinations("abc", 32, ITEMS_LEN)
            .into_iter()
            .enumerate()
        {
            storage_relay
                .insert(index as u64, Bytes::from_hex(item).unwrap())
                .unwrap();
        }
        storage_relay.seal().unwrap();
        let mut relay = Negentropy::new(&mut storage_relay, 0).unwrap();
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
