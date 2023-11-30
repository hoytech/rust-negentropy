use std::convert::TryFrom;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::num::Wrapping;
use core::cmp::Ordering;

use crate::error;

pub use self::error::Error;



pub const PROTOCOL_VERSION_0: u64 = 0x60;
pub const ID_SIZE_TP: usize = 32;
pub const FINGERPRINT_SIZE_TP: usize = 16;

pub const MAX_U64: u64 = u64::MAX;
pub const BUCKETS: usize = 16;
pub const DOUBLE_BUCKETS: usize = BUCKETS * 2;



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Skip = 0,
    Fingerprint = 1,
    IdList = 2,
    Continuation = 3,
    UnsupportedProtocolVersion = 4,
}

impl Mode {
    pub fn as_u64(&self) -> u64 {
        *self as u64
    }
}

impl TryFrom<u64> for Mode {
    type Error = Error;
    fn try_from(mode: u64) -> Result<Self, Self::Error> {
        match mode {
            0 => Ok(Mode::Skip),
            1 => Ok(Mode::Fingerprint),
            2 => Ok(Mode::IdList),
            m => Err(Error::UnexpectedMode(m)),
        }
    }
}

/// Item
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Item {
    pub timestamp: u64,
    pub id_size: usize,
    pub id: [u8; 32],
}

impl Item {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timestamp(timestamp: u64) -> Self {
        let mut item = Self::new();
        item.timestamp = timestamp;
        item
    }

    pub fn with_timestamp_and_id<T>(timestamp: u64, id: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        let id: &[u8] = id.as_ref();
        let len: usize = id.len();

        if len > 32 {
            return Err(Error::IdTooBig);
        }

        let mut item = Self::new();
        item.timestamp = timestamp;
        item.id_size = len;
        item.id[..len].copy_from_slice(id);

        Ok(item)
    }

    pub fn id_size(&self) -> usize {
        self.id_size
    }

    pub fn get_id(&self) -> &[u8] {
        self.id.get(..self.id_size).unwrap_or_default()
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.timestamp != other.timestamp {
            self.timestamp.cmp(&other.timestamp)
        } else {
            self.id.cmp(&other.id)
        }
    }
}


/// Fingerprint
#[derive(Debug, Clone, Copy, Default)]
pub struct Fingerprint {
    buf: [u8; FINGERPRINT_SIZE_TP],
}

impl Fingerprint {
    /// New Fingerprint
    pub fn new() -> Self {
        Self::default()
    }
}


/// Accumulator
#[derive(Debug, Clone, Copy, Default)]
pub struct Accumulator {
    buf: [u8; ID_SIZE_TP],
}

impl Accumulator {
    /// New Accumulator
    pub fn new() -> Self {
        Self {
            buf: [0; ID_SIZE_TP],
        }
    }

    /// Add Item
    pub fn add_item(&mut self, item: &Item) {
        self.add(&item.id);
    }

    /// Add Accum
    pub fn add_accum(&mut self, accum: &Accumulator) {
        self.add(&accum.buf);
    }

    /// Add
    pub fn add(&mut self, buf: &[u8; ID_SIZE_TP]) -> () {
        let mut curr_carry = Wrapping(0u64);
        let mut next_carry = Wrapping(0u64);

        let mut p = Cursor::new(self.buf);
        let mut po = Cursor::new(buf);

        let mut wtr = vec![];

        for _i in 0..4 {
            let orig = Wrapping(p.read_u64::<LittleEndian>().unwrap());
            let other_v = Wrapping(po.read_u64::<LittleEndian>().unwrap());

            let mut next = orig;

            next += curr_carry;
            if next < orig { next_carry = Wrapping(1u64); }

            next += other_v;
            if next < other_v { next_carry = Wrapping(1u64); }

            wtr.write_u64::<LittleEndian>(next.0).unwrap();
            curr_carry = next_carry;
            next_carry = Wrapping(0u64);
        }

        self.buf[0..ID_SIZE_TP].copy_from_slice(&wtr);
    }

    /// Negate
    pub fn negate(&mut self) -> () {
        for i in 0..ID_SIZE_TP {
            self.buf[i] = !self.buf[i];
        }

        let mut one = Accumulator::new();
        one.buf[0] = 1u8;
        self.add(&one.buf);
    }

    /// Sub Item
    pub fn sub_item(&mut self, item: &Item) {
        self.sub(&item.id);
    }

    /// Sub Accum
    pub fn sub_accum(&mut self, accum: &Accumulator) {
        self.sub(&accum.buf);
    }

    /// Sub
    pub fn sub(&mut self, buf: &[u8; ID_SIZE_TP]) -> () {
        let mut neg = Accumulator::new();
        neg.buf = *buf;
        neg.negate();
        self.add_accum(&neg);
    }
}
