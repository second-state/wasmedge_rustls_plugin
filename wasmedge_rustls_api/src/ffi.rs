mod rustls_client {
    #[link(wasm_import_module = "rustls_client")]
    extern "C" {
        pub fn default_config() -> i32;
        pub fn new_codec(config: i32, server_ptr: i32, server_len: i32) -> i32;
        pub fn codec_is_handshaking(codec_id: i32) -> i32;
        pub fn codec_wants(codec_id: i32) -> i32;
        pub fn delete_codec(codec_id: i32) -> i32;
        pub fn write_tls(
            codec_id: i32,
            raw_buf_ptr: i32,
            raw_buf_len: i32,
            tls_buf_ptr: i32,
            tls_buf_len: i32,
            read_num_ptr: i32,
            write_num_ptr: i32,
        ) -> i32;
        pub fn read_tls(
            codec_id: i32,
            tls_buf_ptr: i32,
            tls_buf_len: i32,
            raw_buf_ptr: i32,
            raw_buf_len: i32,
            read_num_ptr: i32,
            write_num_ptr: i32,
        ) -> i32;
    }
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
            -25 => TlsError::IO,
            _ => TlsError::ParamError,
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

pub struct TlsClientCodec {
    id: i32,
}

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

    pub fn write_tls(
        &mut self,
        raw_buf: &[u8],
        tls_buf: &mut [u8],
    ) -> Result<(usize, usize), TlsError> {
        unsafe {
            let mut read_num = 0;
            let mut write_num = 0;
            let e = rustls_client::write_tls(
                self.id,
                raw_buf.as_ptr() as i32,
                raw_buf.len() as i32,
                tls_buf.as_mut_ptr() as i32,
                tls_buf.len() as i32,
                &mut read_num as *mut _ as i32,
                &mut write_num as *mut _ as i32,
            );
            if e < 0 {
                return Err(e.into());
            };
            Ok((read_num as usize, write_num as usize))
        }
    }

    pub fn read_tls(
        &mut self,
        tls_buf: &[u8],
        raw_buf: &mut [u8],
    ) -> Result<(usize, usize), TlsError> {
        unsafe {
            let mut read_num = 0;
            let mut write_num = 0;
            let e = rustls_client::read_tls(
                self.id,
                tls_buf.as_ptr() as i32,
                tls_buf.len() as i32,
                raw_buf.as_mut_ptr() as i32,
                raw_buf.len() as i32,
                &mut read_num as *mut _ as i32,
                &mut write_num as *mut _ as i32,
            );
            if e < 0 {
                return Err(e.into());
            };
            Ok((read_num as usize, write_num as usize))
        }
    }
}

impl Drop for TlsClientCodec {
    fn drop(&mut self) {
        unsafe { rustls_client::delete_codec(self.id) };
    }
}
