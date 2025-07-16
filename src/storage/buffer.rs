use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::path::Path;

pub use super::iter::BincodeIterator;

const DEFAULT_BUFFER_SIZE: usize = 1000;

pub trait Storage<T>
where
    Self: Sized,
{

    fn buffer_mut(&mut self) -> &mut Vec<T>;


    fn flush(&mut self) -> Result<(), Box<dyn Error>>;



    fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.buffer_mut().push(item);

        if self.buffer_mut().len() >= self.buffer_mut().capacity() {
            self.flush()?;
        }
        Ok(())
    }


    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        self.flush()
    }
}

impl<T> Storage<T> for Vec<T> {
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        self
    }


    fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.push(item);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub struct BincodeObjectBuffer<T> {

    writer: BufWriter<RWHandle>,


    buffer: Vec<T>,


    encode_buffer: Vec<u8>,
}

impl<T> BincodeObjectBuffer<T> {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        Ok(BincodeObjectBuffer {
            writer: BufWriter::new(RWHandle::open(file_path)?),
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            encode_buffer: Vec::new(),
        })
    }

    pub fn new_with_capacity(
        file_path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(BincodeObjectBuffer {
            writer: BufWriter::new(RWHandle::open(file_path)?),
            buffer: Vec::with_capacity(capacity),
            encode_buffer: Vec::new(),
        })
    }
}

impl<T: bincode::Decode<()>> BincodeObjectBuffer<T> {
    pub fn into_reader(
        self,
    ) -> Result<BincodeIterator<T, BufReader<std::fs::File>>, Box<dyn Error>> {
        let mut inner = self.writer.into_inner()?;
        inner.0.seek(std::io::SeekFrom::Start(0))?;
        Ok(BincodeIterator::from_file(inner.0))
    }
}

impl<T> Storage<T> for BincodeObjectBuffer<T>
where
    T: bincode::Encode,
{
    #[inline]
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        &mut self.buffer
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        for item in self.buffer.drain(..) {
            self.encode_buffer.clear();
            bincode::encode_into_std_write(
                &item,
                &mut self.encode_buffer,
                bincode::config::standard(),
            )?;

            let len = self.encode_buffer.len() as u32;
            self.writer.write_all(&len.to_le_bytes())?;
            self.writer.write_all(&self.encode_buffer)?;
        }

        self.writer.flush()?;

        Ok(())
    }
}




#[derive(Debug)]
struct RWHandle(std::fs::File);

impl RWHandle {
    pub fn open(file_path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true) // read so we can read back the file later
            .truncate(true)
            .open(file_path)?;

        Ok(RWHandle(file))
    }
}

impl std::io::Write for RWHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
