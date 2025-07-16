use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};
use std::marker::PhantomData;

pub type DiskStorageReader<T> = BincodeIterator<T, BufReader<File>>;


pub struct BincodeIterator<T, R: Read> {
    reader: R,
    _phantom: PhantomData<T>,
}

impl<T> BincodeIterator<T, BufReader<File>>
where
    T: bincode::Decode<()>,
{

    pub fn from_path(file_path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        Ok(Self {
            reader,
            _phantom: PhantomData,
        })
    }

    pub fn from_file(file: std::fs::File) -> Self {
        Self {
            reader: BufReader::new(file),
            _phantom: PhantomData,
        }
    }
}

impl<T, R: Read> BincodeIterator<T, R>
where
    T: bincode::Decode<()>,
{

    pub fn new(reader: R) -> Self {
        Self {
            reader,
            _phantom: PhantomData,
        }
    }
}

impl<T, R: Read> Iterator for BincodeIterator<T, R>
where
    T: bincode::Decode<()>,
{
    type Item = Result<T, Box<dyn Error>>;

    fn next(&mut self) -> Option<Self::Item> {

        let mut len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {

                return None;
            }
            Err(e) => return Some(Err(e.into())),
        }

        let len = u32::from_le_bytes(len_bytes) as usize;











        let mut data = vec![0u8; len];
        if let Err(e) = self.reader.read_exact(&mut data) {
            return Some(Err(format!("Failed to read {len} bytes: {e}").into()));
        }


        match bincode::decode_from_slice::<T, _>(&data, bincode::config::standard()) {
            Ok((item, _)) => Some(Ok(item)),
            Err(e) => Some(Err(format!("Failed to decode item: {e:?}").into())),
        }
    }
}
