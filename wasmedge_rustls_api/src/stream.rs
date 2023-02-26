use std::io::{Read, Result, Write};

use crate::TlsClientCodec;

#[derive(Debug)]
pub struct Stream<'a, C: 'a + ?Sized, T: 'a + Read + Write + ?Sized> {
    pub conn: &'a mut C,
    pub sock: &'a mut T,
}

impl<'a, T> Stream<'a, TlsClientCodec, T>
where
    T: 'a + Read + Write,
{
    pub fn new(conn: &'a mut TlsClientCodec, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }

    fn complete_prior_io(&mut self) -> Result<()> {
        if self.conn.is_handshaking() {
            crate::complete_io(self.conn, self.sock)?;
        }

        if self.conn.wants().wants_write {
            crate::complete_io(self.conn, self.sock)?;
        }

        Ok(())
    }
}

impl<'a, T> Read for Stream<'a, TlsClientCodec, T>
where
    T: 'a + Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.complete_prior_io()?;

        while self.conn.wants().wants_read {
            let at_eof = crate::complete_io(self.conn, self.sock)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.conn.process_new_packets() {
                    if at_eof && io_state.plaintext_bytes_to_read == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        Ok(self.conn.read_raw(buf)?)
    }
}

impl<'a, T> Write for Stream<'a, TlsClientCodec, T>
where
    T: 'a + Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.conn.write_raw(buf)?;

        let _ = crate::complete_io(self.conn, self.sock);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        if self.conn.wants().wants_write {
            crate::complete_io(self.conn, self.sock)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct StreamOwned<C: Sized, T: Read + Write + Sized> {
    pub conn: C,

    pub sock: T,
}

impl<T> StreamOwned<TlsClientCodec, T>
where
    T: Read + Write,
{
    pub fn new(conn: TlsClientCodec, sock: T) -> Self {
        Self { conn, sock }
    }

    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }
}

impl<'a, T> StreamOwned<TlsClientCodec, T>
where
    T: Read + Write,
{
    fn as_stream(&'a mut self) -> Stream<'a, TlsClientCodec, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<T> Read for StreamOwned<TlsClientCodec, T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<T> Write for StreamOwned<TlsClientCodec, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.as_stream().flush()
    }
}
