pub mod buffer;
pub mod iter;
use std::error::Error;

pub use buffer::{BincodeObjectBuffer, Storage};

use crate::ldap::LdapSearchEntry;
pub use iter::DiskStorageReader;

pub type DiskStorage = BincodeObjectBuffer<LdapSearchEntry>;





pub trait EntrySource {
    type Iter: Iterator<Item = Result<LdapSearchEntry, Box<dyn Error>>>;
    fn into_entry_iter(self) -> Self::Iter;
}


impl EntrySource for DiskStorageReader<LdapSearchEntry> {
    type Iter = Self;

    fn into_entry_iter(self) -> Self::Iter {
        self
    }
}


impl EntrySource for Vec<LdapSearchEntry> {
    type Iter = std::iter::Map<
        std::vec::IntoIter<LdapSearchEntry>,
        fn(LdapSearchEntry) -> Result<LdapSearchEntry, Box<dyn Error>>,
    >;

    fn into_entry_iter(self) -> Self::Iter {
        self.into_iter().map(Ok)
    }
}
