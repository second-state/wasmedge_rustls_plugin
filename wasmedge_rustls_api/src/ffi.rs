use std::fmt::Display;

mod rustls_client {
    #[link(wasm_import_module = "rustls_client")]
    extern "C" {
        pub fn default_config() -> i32;
        pub fn new_codec(config: i32, server_ptr: i32, server_len: i32) -> i32;
        pub fn codec_is_handshaking(codec_id: i32) -> i32;
        pub fn codec_wants(codec_id: i32) -> i32;
        pub fn delete_codec(codec_id: i32) -> i32;
        pub fn send_close_notify(codec_id: i32) -> i32;
        pub fn process_new_packets(codec_id: i32, io_state_ptr: i32) -> i32;
        pub fn write_tls(codec_id: i32, buf_ptr: i32, buf_len: i32) -> i32;
        pub fn write_raw(codec_id: i32, buf_ptr: i32, buf_len: i32) -> i32;
        pub fn read_tls(codec_id: i32, buf_ptr: i32, buf_len: i32) -> i32;
        pub fn read_raw(codec_id: i32, buf_ptr: i32, buf_len: i32) -> i32;
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct TlsIoState {
    pub tls_bytes_to_write: u32,
    pub plaintext_bytes_to_read: u32,
    pub peer_has_closed: bool,
}

// see rustls::Error
#[derive(Debug, Clone, Copy)]
pub enum TlsError {
    ParamError,
    InappropriateMessage,
    InappropriateHandshakeMessage,
    CorruptMessage,
    CorruptMessagePayload,
    NoCertificatesPresented,
    UnsupportedNameType,
    DecryptError,
    EncryptError,
    PeerIncompatibleError,
    PeerMisbehavedError,
    AlertReceived,
    InvalidCertificateEncoding,
    InvalidCertificateSignatureType,
    InvalidCertificateSignature,
    InvalidCertificateData,
    InvalidSct,
    General,
    FailedToGetCurrentTime,
    FailedToGetRandomBytes,
    HandshakeNotComplete,
    PeerSentOversizedRecord,
    NoApplicationProtocol,
    BadMaxFragmentSize,
    IOWouldBlock,
    IO,
}

impl Into<TlsError> for i32 {
    fn into(self) -> TlsError {
        match self {
            -1 => TlsError::ParamError,
            -2 => TlsError::InappropriateMessage,
            -3 => TlsError::InappropriateHandshakeMessage,
            -4 => TlsError::CorruptMessage,
            -5 => TlsError::CorruptMessagePayload,
            -6 => TlsError::NoCertificatesPresented,
            -7 => TlsError::UnsupportedNameType,
            -8 => TlsError::DecryptError,
            -9 => TlsError::EncryptError,
            -10 => TlsError::PeerIncompatibleError,
            -11 => TlsError::PeerMisbehavedError,
            -12 => TlsError::AlertReceived,
            -13 => TlsError::InvalidCertificateEncoding,
            -14 => TlsError::InvalidCertificateSignatureType,
            -15 => TlsError::InvalidCertificateSignature,
            -16 => TlsError::InvalidCertificateData,
            -17 => TlsError::InvalidSct,
            -18 => TlsError::General,
            -19 => TlsError::FailedToGetCurrentTime,
            -20 => TlsError::FailedToGetRandomBytes,
            -21 => TlsError::HandshakeNotComplete,
            -22 => TlsError::PeerSentOversizedRecord,
            -23 => TlsError::NoApplicationProtocol,
            -24 => TlsError::BadMaxFragmentSize,
            -25 => TlsError::IOWouldBlock,
            -26 => TlsError::IO,
            _ => TlsError::ParamError,
        }
    }
}

impl Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TlsError {}

impl From<TlsError> for std::io::Error {
    fn from(value: TlsError) -> Self {
        if let TlsError::IOWouldBlock = value {
            std::io::ErrorKind::WouldBlock.into()
        } else {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, value)
        }
    }
}
pub struct ClientConfig {
    id: i32,
}

impl ClientConfig {
    pub fn new_codec<S: AsRef<str>>(&self, server_name: S) -> Result<TlsClientCodec, TlsError> {
        unsafe {
            let server_name = server_name.as_ref();
            let server_ptr = server_name.as_ptr();
            let server_len = server_name.len();
            let id = rustls_client::new_codec(self.id, server_ptr as i32, server_len as i32);
            if id < 0 {
                return Err(id.into());
            }
            Ok(TlsClientCodec { id })
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        let id = unsafe { rustls_client::default_config() };
        Self { id }
    }
}

#[derive(Debug)]
pub struct TlsClientCodec {
    id: i32,
}

#[derive(Debug)]
pub struct WantsResult {
    pub wants_read: bool,
    pub wants_write: bool,
}

impl TlsClientCodec {
    pub fn is_handshaking(&self) -> bool {
        unsafe { rustls_client::codec_is_handshaking(self.id) > 0 }
    }

    //(wants_read,wants_write)
    pub fn wants(&self) -> WantsResult {
        unsafe {
            let i = rustls_client::codec_wants(self.id);
            WantsResult {
                wants_read: i & 0b01 > 0,
                wants_write: i & 0b010 > 0,
            }
        }
    }

    pub fn send_close_notify(&mut self) -> Result<(), TlsError> {
        unsafe {
            let e = rustls_client::send_close_notify(self.id);
            if e < 0 {
                Err(e.into())
            } else {
                Ok(())
            }
        }
    }

    pub fn process_new_packets(&mut self) -> Result<TlsIoState, TlsError> {
        unsafe {
            let mut io_state = TlsIoState {
                tls_bytes_to_write: 0,
                plaintext_bytes_to_read: 0,
                peer_has_closed: false,
            };
            let e = rustls_client::process_new_packets(
                self.id,
                (&mut io_state) as *mut _ as usize as i32,
            );
            if e < 0 {
                Err(e.into())
            } else {
                Ok(io_state)
            }
        }
    }

    pub fn write_tls(&mut self, tls_buf: &mut [u8]) -> Result<usize, TlsError> {
        unsafe {
            let e =
                rustls_client::write_tls(self.id, tls_buf.as_ptr() as i32, tls_buf.len() as i32);
            if e < 0 {
                Err(e.into())
            } else {
                Ok(e as usize)
            }
        }
    }

    pub fn write_raw(&mut self, raw_buf: &[u8]) -> Result<usize, TlsError> {
        unsafe {
            let e =
                rustls_client::write_raw(self.id, raw_buf.as_ptr() as i32, raw_buf.len() as i32);
            if e < 0 {
                Err(e.into())
            } else {
                Ok(e as usize)
            }
        }
    }

    pub fn read_tls(&mut self, tls_buf: &[u8]) -> Result<usize, TlsError> {
        unsafe {
            let e = rustls_client::read_tls(self.id, tls_buf.as_ptr() as i32, tls_buf.len() as i32);
            if e < 0 {
                Err(e.into())
            } else {
                Ok(e as usize)
            }
        }
    }

    pub fn read_raw(&mut self, raw_buf: &mut [u8]) -> Result<usize, TlsError> {
        unsafe {
            let e = rustls_client::read_raw(self.id, raw_buf.as_ptr() as i32, raw_buf.len() as i32);
            if e < 0 {
                Err(e.into())
            } else {
                Ok(e as usize)
            }
        }
    }
}

impl Drop for TlsClientCodec {
    fn drop(&mut self) {
        unsafe { rustls_client::delete_codec(self.id) };
    }
}

pub fn complete_io<T>(codec: &mut TlsClientCodec, io: &mut T) -> std::io::Result<(usize, usize)>
where
    T: std::io::Read + std::io::Write,
{
    let until_handshaked = codec.is_handshaking();
    let mut eof = false;
    let mut wrlen = 0;
    let mut rdlen = 0;
    let mut buf = [0u8; 1024 * 4];

    loop {
        while codec.wants().wants_write {
            let n = codec.write_tls(&mut buf)?;
            io.write_all(&buf[0..n])?;
            wrlen += n;
        }

        if !until_handshaked && wrlen > 0 {
            return Ok((rdlen, wrlen));
        }

        while !eof && codec.wants().wants_read {
            let n = io.read(&mut buf)?;
            let read_size = match codec.read_tls(&buf[0..n]) {
                Ok(0) => {
                    eof = true;
                    Some(0)
                }
                Ok(n) => {
                    rdlen += n;
                    Some(n)
                }
                Err(err) => return Err(err.into()),
            };
            if read_size.is_some() {
                break;
            }
        }

        match codec.process_new_packets() {
            Ok(_) => {}
            Err(e) => {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let n = codec.write_tls(&mut buf)?;
                let _ignored = io.write_all(&buf[0..n]);

                return Err(e.into());
            }
        };

        match (eof, until_handshaked, codec.is_handshaking()) {
            (_, true, false) => return Ok((rdlen, wrlen)),
            (_, false, _) => return Ok((rdlen, wrlen)),
            (true, true, true) => {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            }
            (..) => {}
        }
    }
}
