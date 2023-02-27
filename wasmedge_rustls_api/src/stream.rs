use std::io::{Read, Result, Write};

use crate::TlsClientCodec;

#[derive(Debug)]
pub struct VecBuffer {
    buf: Vec<u8>,
    pub used: usize,
    pub filled: usize,
}

impl VecBuffer {
    pub fn new(buf: Vec<u8>) -> Self {
        Self {
            buf,
            used: 0,
            filled: 0,
        }
    }
    pub fn from_read<R: Read>(&mut self, rd: &mut R) -> std::io::Result<()> {
        let n = rd.read(self.mut_rest_buf())?;
        self.filled += n;
        Ok(())
    }

    pub fn mut_rest_buf(&mut self) -> &mut [u8] {
        &mut self.buf[self.filled..]
    }

    pub fn get_available_buf(&self) -> &[u8] {
        &self.buf[self.used..self.filled]
    }

    pub fn write_to(
        &mut self,
        f: &mut dyn FnMut(&[u8]) -> std::io::Result<usize>,
    ) -> std::io::Result<usize> {
        let n = f(self.get_available_buf())?;
        self.used += n;
        if self.used == self.filled {
            self.clear();
        }
        Ok(n)
    }

    pub fn clear(&mut self) {
        self.used = 0;
        self.filled = 0;
    }
}

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

#[cfg(feature = "tokio_async")]
pub mod async_stream {
    use std::{
        future::Future,
        io,
        os::fd::{AsRawFd, RawFd},
        pin::Pin,
        task::{ready, Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use crate::{ClientConfig, TlsClientCodec, TlsError};

    use super::VecBuffer;

    #[derive(Debug)]
    pub enum TlsState {
        Stream,
        ReadShutdown,
        WriteShutdown,
        FullyShutdown,
    }

    impl TlsState {
        #[inline]
        pub fn shutdown_read(&mut self) {
            match *self {
                TlsState::WriteShutdown | TlsState::FullyShutdown => {
                    *self = TlsState::FullyShutdown
                }
                _ => *self = TlsState::ReadShutdown,
            }
        }

        #[inline]
        pub fn shutdown_write(&mut self) {
            match *self {
                TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
                _ => *self = TlsState::WriteShutdown,
            }
        }

        #[inline]
        pub fn writeable(&self) -> bool {
            !matches!(*self, TlsState::WriteShutdown | TlsState::FullyShutdown)
        }

        #[inline]
        pub fn readable(&self) -> bool {
            !matches!(*self, TlsState::ReadShutdown | TlsState::FullyShutdown)
        }

        #[inline]
        pub const fn is_early_data(&self) -> bool {
            false
        }
    }

    pub struct AsyncStream<'a, IO, C> {
        pub io: &'a mut IO,
        pub session: &'a mut C,
        read_buf: VecBuffer,
        write_buf: VecBuffer,
        pub eof: bool,
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncStream<'a, IO, TlsClientCodec> {
        pub fn new(io: &'a mut IO, session: &'a mut TlsClientCodec) -> Self {
            AsyncStream {
                io,
                session,
                read_buf: VecBuffer::new(vec![0u8; 1024 * 4]),
                write_buf: VecBuffer::new(vec![0u8; 1024 * 4]),
                eof: false,
            }
        }

        pub fn set_eof(mut self, eof: bool) -> Self {
            self.eof = eof;
            self
        }

        pub fn as_mut_pin(&mut self) -> Pin<&mut Self> {
            Pin::new(self)
        }

        pub fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(self.read_buf.mut_rest_buf());
            let r = Pin::new(&mut self.io).poll_read(cx, &mut buf);
            let n = match r {
                Poll::Ready(Ok(())) => buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.read_buf.filled += n;

            let n = match self
                .read_buf
                .write_to(&mut |buf| self.session.read_tls(buf).map_err(|e| e.into()))
            {
                Ok(n) => n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(err) => return Poll::Ready(Err(err)),
            };

            let stats = self.session.process_new_packets().map_err(|err| {
                let _ = self.write_io(cx);
                io::Error::new(io::ErrorKind::InvalidData, err)
            })?;

            if stats.peer_has_closed && self.session.is_handshaking() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake alert",
                )));
            }

            Poll::Ready(Ok(n))
        }

        pub fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
            let r = self.session.write_tls(self.write_buf.mut_rest_buf());
            if let Ok(n) = r {
                self.write_buf.filled += n;
            }
            if self.write_buf.filled > self.write_buf.used {
                let n = match Pin::new(&mut self.io)
                    .poll_write(cx, self.write_buf.get_available_buf())
                {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                };
                self.write_buf.used += n;
                if self.write_buf.used == self.write_buf.filled {
                    self.write_buf.clear();
                }

                Poll::Ready(Ok(n))
            } else {
                if let Err(e) = r {
                    if let TlsError::IOWouldBlock = e {
                        return Poll::Pending;
                    } else {
                        return Poll::Ready(Err(e.into()));
                    }
                } else {
                    let r =
                        Pin::new(&mut self.io).poll_write(cx, self.write_buf.get_available_buf());
                    let n = match r {
                        Poll::Ready(Ok(n)) => n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    self.write_buf.used += n;
                    if self.write_buf.used == self.write_buf.filled {
                        self.write_buf.clear();
                    }

                    Poll::Ready(Ok(n))
                }
            }
        }

        pub fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
            let mut wrlen = 0;
            let mut rdlen = 0;

            loop {
                let mut write_would_block = false;
                let mut read_would_block = false;
                let mut need_flush = false;

                while self.session.wants().wants_write {
                    match self.write_io(cx) {
                        Poll::Ready(Ok(n)) => {
                            wrlen += n;
                            need_flush = true;
                        }
                        Poll::Pending => {
                            write_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(err));
                        }
                    }
                }

                if need_flush {
                    match Pin::new(&mut self.io).poll_flush(cx) {
                        Poll::Ready(Ok(())) => (),
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(err));
                        }
                        Poll::Pending => write_would_block = true,
                    }
                }

                while !self.eof && self.session.wants().wants_read {
                    match self.read_io(cx) {
                        Poll::Ready(Ok(0)) => self.eof = true,
                        Poll::Ready(Ok(n)) => rdlen += n,
                        Poll::Pending => {
                            read_would_block = true;
                            break;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(err));
                        }
                    }
                }

                return match (self.eof, self.session.is_handshaking()) {
                    (true, true) => {
                        let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                        Poll::Ready(Err(err))
                    }
                    (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                    (_, true) if write_would_block || read_would_block => {
                        if rdlen != 0 || wrlen != 0 {
                            Poll::Ready(Ok((rdlen, wrlen)))
                        } else {
                            Poll::Pending
                        }
                    }
                    (..) => continue,
                };
            }
        }
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncStream<'a, IO, TlsClientCodec> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut io_pending = false;

            // read a packet
            while !self.eof && self.session.wants().wants_read {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        break;
                    }
                    Poll::Ready(Ok(_)) => (),
                    Poll::Pending => {
                        io_pending = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            match self.session.read_raw(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(TlsError::IOWouldBlock) => {
                    if !io_pending {
                        cx.waker().wake_by_ref();
                    }

                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err.into())),
            }
        }
    }

    impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncStream<'a, IO, TlsClientCodec> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut pos = 0;

            while pos != buf.len() {
                let mut would_block = false;

                match self.session.write_raw(&buf[pos..]) {
                    Ok(n) => pos += n,
                    Err(err) => return Poll::Ready(Err(err.into())),
                };

                while self.session.wants().wants_write {
                    match self.write_io(cx) {
                        Poll::Ready(Ok(0)) | Poll::Pending => {
                            would_block = true;
                            break;
                        }
                        Poll::Ready(Ok(_)) => (),
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }

                return match (pos, would_block) {
                    (0, true) => Poll::Pending,
                    (n, true) => Poll::Ready(Ok(n)),
                    (_, false) => continue,
                };
            }

            Poll::Ready(Ok(pos))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            while self.session.wants().wants_write {
                ready!(self.write_io(cx))?;
            }
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.session.wants().wants_write {
                ready!(self.write_io(cx))?;
            }
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    pub enum MidHandshake<IO: AsyncRead + AsyncWrite + Unpin> {
        Handshaking(TlsStream<IO>),
        End,
        Error { io: IO, error: io::Error },
    }

    impl<IO> Future for MidHandshake<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        type Output = Result<TlsStream<IO>, (io::Error, IO)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            let mut stream = match std::mem::replace(this, MidHandshake::End) {
                MidHandshake::Handshaking(stream) => stream,
                MidHandshake::Error { io, error } => return Poll::Ready(Err((error, io))),
                _ => panic!("unexpected polling after handshake"),
            };

            if !stream.skip_handshake() {
                let (state, io, session) = stream.get_session_mut();
                let mut tls_stream = AsyncStream::new(io, session).set_eof(!state.readable());

                macro_rules! try_poll {
                    ( $e:expr ) => {
                        match $e {
                            Poll::Ready(Ok(_)) => (),
                            Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.io))),
                            Poll::Pending => {
                                *this = MidHandshake::Handshaking(stream);
                                return Poll::Pending;
                            }
                        }
                    };
                }

                while tls_stream.session.is_handshaking() {
                    try_poll!(tls_stream.handshake(cx));
                }

                try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
            }

            Poll::Ready(Ok(stream))
        }
    }

    #[derive(Debug)]
    pub struct TlsStream<IO> {
        pub(crate) io: IO,
        pub(crate) session: TlsClientCodec,
        pub(crate) state: TlsState,
    }

    impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
        pub async fn connect<S: AsRef<str>>(
            config: &ClientConfig,
            domain: S,
            io: IO,
        ) -> Result<Self, (std::io::Error, IO)> {
            let session = match config.new_codec(domain) {
                Ok(s) => s,
                Err(e) => return Err((e.into(), io)),
            };
            let tls_stream = TlsStream {
                io,
                session,
                state: TlsState::Stream,
            };
            Ok(MidHandshake::Handshaking(tls_stream).await?)
        }

        #[inline]
        pub fn get_ref(&self) -> (&IO, &TlsClientCodec) {
            (&self.io, &self.session)
        }

        #[inline]
        pub fn get_mut(&mut self) -> (&mut IO, &mut TlsClientCodec) {
            (&mut self.io, &mut self.session)
        }

        #[inline]
        pub fn into_inner(self) -> (IO, TlsClientCodec) {
            (self.io, self.session)
        }

        #[inline]
        fn skip_handshake(&self) -> bool {
            self.state.is_early_data()
        }

        #[inline]
        fn get_session_mut(&mut self) -> (&mut TlsState, &mut IO, &mut TlsClientCodec) {
            (&mut self.state, &mut self.io, &mut self.session)
        }
    }

    impl<S> AsRawFd for TlsStream<S>
    where
        S: AsRawFd,
    {
        fn as_raw_fd(&self) -> RawFd {
            self.io.as_raw_fd()
        }
    }

    impl<IO> AsyncRead for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.state {
                TlsState::Stream | TlsState::WriteShutdown => {
                    let this = self.get_mut();
                    let mut stream = AsyncStream::new(&mut this.io, &mut this.session)
                        .set_eof(!this.state.readable());
                    let prev = buf.remaining();

                    match stream.as_mut_pin().poll_read(cx, buf) {
                        Poll::Ready(Ok(())) => {
                            if prev == buf.remaining() || stream.eof {
                                this.state.shutdown_read();
                            }

                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionAborted => {
                            this.state.shutdown_read();
                            Poll::Ready(Err(err))
                        }
                        output => output,
                    }
                }
                TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(())),
            }
        }
    }

    impl<IO> AsyncWrite for TlsStream<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut stream =
                AsyncStream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
            stream.as_mut_pin().poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut stream =
                AsyncStream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

            stream.as_mut_pin().poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.state.writeable() {
                let _ = self.session.send_close_notify();
                self.state.shutdown_write();
            }

            let this = self.get_mut();
            let mut stream =
                AsyncStream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
            stream.as_mut_pin().poll_shutdown(cx)
        }
    }
}
