use crate::error;
use crate::types;
use crate::bytes;

pub use self::bytes::Bytes;
pub use self::error::Error;
pub use self::types::{ID_SIZE, Item, Bound, Accumulator, Fingerprint};




/// NegentropyStorageBase
pub trait NegentropyStorageBase {
    /// Size
    fn size(&self) -> Result<usize, Error>;

    /// Get Item
    fn get_item(&self, i: usize) -> Result<Item, Error>;

    /// Iterate
    fn iterate(&self, begin: usize, end: usize, cb: &mut dyn FnMut(Item, usize) -> bool) -> Result<(), Error>;

    /// Find Lower Bound
    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize;

    /// Fingerprint
    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error>;
}

/// NegentropyStorageVector
#[derive(Debug, Clone)]
pub struct NegentropyStorageVector {
    items: Vec<Item>,
    sealed: bool,
}

impl NegentropyStorageBase for NegentropyStorageVector {
    fn size(&self) -> Result<usize, Error> {
        self.check_sealed()?;
        Ok(self.items.len())
    }

    fn get_item(&self, i: usize) -> Result<Item, Error> {
        self.check_sealed()?;
        Ok(self.items[i])
    }

    fn iterate(&self, begin: usize, end: usize, cb: &mut dyn FnMut(Item, usize) -> bool) -> Result<(), Error> {
        self.check_sealed()?;
        self.check_bounds(begin, end)?;

        for i in begin..end {
            if !cb(self.items[i], i) {
                break;
            }
        }

        Ok(())
    }

    fn find_lower_bound(&self, mut first: usize, last: usize, value: &Bound) -> usize {
        let mut count: usize = last - first;

        while count > 0 {
            let mut it: usize = first;
            let step: usize = count / 2;
            it += step;

            if self.items[it] < value.item {
                it += 1;
                first = it;
                count -= step + 1;
            } else {
                count = step;
            }
        }

        first
    }

    fn fingerprint(&self, begin: usize, end: usize) -> Result<Fingerprint, Error> {
        let mut out = Accumulator::new();

        self.iterate(begin, end, &mut |item: Item, _| {
            out.add(&item.id);
            true
        })?;

        Ok(out.get_fingerprint((end - begin) as u64))
    }
}

impl NegentropyStorageVector {
    /// Create new [`NegentropyStorageVector`] instance
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            items: Vec::new(),
            sealed: false,
        })
    }

    /// Add item
    pub fn add_item(&mut self, created_at: u64, id: Bytes) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::AlreadySealed);
        }

        let id: &[u8] = id.as_ref();
        if id.len() != ID_SIZE {
            return Err(Error::IdSizeNotMatch);
        }

        let elem: Item = Item::with_timestamp_and_id(created_at, &id)?;

        self.items.push(elem);
        Ok(())
    }

    /// Seal
    pub fn seal(&mut self) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::AlreadySealed);
        }
        self.sealed = true;

        self.items.sort();

        for i in 1..self.items.len() {
            if self.items[i - 1] == self.items[i] {
                return Err(Error::DuplicateItemAdded);
            }
        }

        Ok(())
    }

    fn check_sealed(&self) -> Result<(), Error> {
        if !self.sealed {
            return Err(Error::NotSealed);
        }
        Ok(())
    }

    fn check_bounds(&self, begin: usize, end: usize) -> Result<(), Error> {
        if begin > end || end > self.items.len() {
            return Err(Error::BadRange);
        }
        Ok(())
    }
}
