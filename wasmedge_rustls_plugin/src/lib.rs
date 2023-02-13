use std::ptr::null_mut;

use thiserror::Error;
use wasmedge_sys_ffi as ffi;

pub mod core;
mod error;
mod utils;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("{0}")]
    Tls(#[from] rustls::Error),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("ParamError")]
    ParamError,
}

impl TlsError {
    pub fn error_code(&self) -> i32 {
        match self {
            TlsError::ParamError => -1,
            TlsError::Tls(tls_err) => match tls_err {
                rustls::Error::InappropriateMessage { .. } => -2,
                rustls::Error::InappropriateHandshakeMessage { .. } => -3,
                rustls::Error::CorruptMessage => -4,
                rustls::Error::CorruptMessagePayload(_) => -5,
                rustls::Error::NoCertificatesPresented => -6,
                rustls::Error::UnsupportedNameType => -7,
                rustls::Error::DecryptError => -8,
                rustls::Error::EncryptError => -9,
                rustls::Error::PeerIncompatibleError(_) => -10,
                rustls::Error::PeerMisbehavedError(_) => -11,
                rustls::Error::AlertReceived(_) => -12,
                rustls::Error::InvalidCertificateEncoding => -13,
                rustls::Error::InvalidCertificateSignatureType => -14,
                rustls::Error::InvalidCertificateSignature => -15,
                rustls::Error::InvalidCertificateData(_) => -16,
                rustls::Error::InvalidSct(_) => -17,
                rustls::Error::General(_) => -18,
                rustls::Error::FailedToGetCurrentTime => -19,
                rustls::Error::FailedToGetRandomBytes => -20,
                rustls::Error::HandshakeNotComplete => -21,
                rustls::Error::PeerSentOversizedRecord => -22,
                rustls::Error::NoApplicationProtocol => -23,
                rustls::Error::BadMaxFragmentSize => -24,
            },
            TlsError::IO(_) => -25,
        }
    }
}

mod tls_client {
    use std::{
        io::{Read, Write},
        sync::Arc,
    };

    use bytes::{Buf, BufMut};
    use rustls::{OwnedTrustAnchor, RootCertStore};

    use crate::TlsError;

    pub struct Ctx {
        pub client_configs: Vec<Option<Arc<rustls::ClientConfig>>>,
        pub client_codec: Vec<Option<ClientCodec>>,
    }

    impl Ctx {
        pub fn new() -> Ctx {
            let mut root_store = RootCertStore::empty();
            root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ctx {
                client_configs: vec![Some(Arc::new(config))],
                client_codec: Vec::with_capacity(1024),
            }
        }

        pub fn default_client_config(&mut self) -> usize {
            0
        }

        pub fn new_codec(
            &mut self,
            server_name: &str,
            config_id: usize,
        ) -> Result<usize, TlsError> {
            let config = self
                .client_configs
                .get(config_id)
                .ok_or(TlsError::ParamError)?
                .clone()
                .ok_or(TlsError::ParamError)?;

            let name = server_name.try_into().map_err(|_| TlsError::ParamError)?;
            let new_codec = rustls::ClientConnection::new(config, name)?;
            let new_codec = ClientCodec(new_codec);

            if let Some((id, item)) = self
                .client_codec
                .iter_mut()
                .enumerate()
                .find(|(_, item)| item.is_none())
            {
                debug_assert!(item.is_none());
                let _ = item.insert(new_codec);
                Ok(id)
            } else {
                let id = self.client_codec.len();
                self.client_codec.push(Some(new_codec));
                Ok(id)
            }
        }

        pub fn delete_codec(&mut self, codec_id: usize) {
            if let Some(codec) = self.client_codec.get_mut(codec_id) {
                let _ = codec.take();
            }
        }
    }

    #[derive(Debug)]
    pub struct ClientCodec(pub rustls::ClientConnection);

    impl ClientCodec {
        pub fn is_handshaking(&self) -> bool {
            self.0.is_handshaking()
        }

        pub fn write_tls(
            &mut self,
            raw_buf: &[u8],
            tls_buf: &mut [u8],
        ) -> Result<(usize, usize), TlsError> {
            let conn = &mut self.0;
            if conn.is_handshaking() || raw_buf.is_empty() {
                let wn = conn.write_tls(&mut tls_buf.writer())?;
                Ok((0, wn))
            } else {
                let rn = conn.writer().write(raw_buf)?;
                let wn = conn.write_tls(&mut tls_buf.writer())?;
                Ok((rn, wn))
            }
        }

        pub fn read_tls(
            &mut self,
            tls_buf: &[u8],
            raw_buf: &mut [u8],
        ) -> Result<(usize, usize), TlsError> {
            let conn = &mut self.0;
            let rn = if !tls_buf.is_empty() {
                conn.read_tls(&mut tls_buf.reader())?
            } else {
                0
            };

            let io_state = conn.process_new_packets()?;
            let wn = if io_state.plaintext_bytes_to_read() > 0 {
                conn.reader().read(raw_buf)?
            } else {
                0
            };

            Ok((rn, wn))
        }
    }

    #[cfg(test)]
    mod tls_client_test {
        use super::*;
        #[test]
        fn test_ctx() {
            let mut ctx = Ctx::new();
            let config_id = ctx.default_client_config();
            assert_eq!(config_id, 0);

            let codec_id_0 = ctx.new_codec("httpbin.org", config_id).unwrap();
            assert_eq!(codec_id_0, 0);
            let codec_id_1 = ctx.new_codec("httpbin.org", config_id).unwrap();
            assert_eq!(codec_id_1, 1);
            ctx.delete_codec(codec_id_0);
            println!("{:?}", ctx.client_codec);
            let codec_id_0 = ctx.new_codec("httpbin.org", config_id).unwrap();
            assert_eq!(codec_id_0, 0);
        }
    }
}

mod wasmedge_client_plugin {

    use crate::{
        core::{
            instance::memory::Memory,
            types::{ValType, WasmVal},
        },
        error::CoreError,
        tls_client::*,
        TlsError,
    };

    use wasmedge_sys_ffi as ffi;

    fn default_config(
        _memory: &mut Memory,
        ctx: &mut Ctx,
        _args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        let config_id = ctx.default_client_config();
        Ok(vec![WasmVal::I32(config_id as i32)])
    }

    fn new_client_codec(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn new_client_codec_inner(
            memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            let config_id = args[0].clone();
            let server_ptr = args[1].clone();
            let server_len = args[2].clone();

            if let (WasmVal::I32(config_id), WasmVal::I32(server_ptr), WasmVal::I32(server_len)) =
                (config_id, server_ptr, server_len)
            {
                let server_name = memory.data_pointer(server_ptr as usize, server_len as usize);
                let server_name = server_name
                    .and_then(|bs| std::str::from_utf8(bs).ok())
                    .ok_or(TlsError::ParamError)?;
                let r = ctx.new_codec(server_name, config_id as usize)?;
                Ok(WasmVal::I32(r as i32))
            } else {
                Err(TlsError::ParamError)
            }
        }
        match new_client_codec_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    fn is_handshaking(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn is_handshaking_inner(
            _memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            if let WasmVal::I32(codec_id) = args[0].clone() {
                let codec = ctx
                    .client_codec
                    .get(codec_id as usize)
                    .ok_or(TlsError::ParamError)?
                    .as_ref()
                    .ok_or(TlsError::ParamError)?;
                if codec.is_handshaking() {
                    Ok(WasmVal::I32(1))
                } else {
                    Ok(WasmVal::I32(0))
                }
            } else {
                Err(TlsError::ParamError)
            }
        }

        match is_handshaking_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    fn wants(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn wants_inner(
            _memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            if let WasmVal::I32(codec_id) = args[0].clone() {
                let codec = ctx
                    .client_codec
                    .get(codec_id as usize)
                    .ok_or(TlsError::ParamError)?
                    .as_ref()
                    .ok_or(TlsError::ParamError)?;
                match (codec.0.wants_write(), codec.0.wants_read()) {
                    (true, true) => Ok(WasmVal::I32(0b11)),
                    (true, false) => Ok(WasmVal::I32(0b10)),
                    (false, true) => Ok(WasmVal::I32(0b01)),
                    (false, false) => Ok(WasmVal::I32(0)),
                }
            } else {
                Err(TlsError::ParamError)
            }
        }

        match wants_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    fn delete_codec(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn delete_codec_inner(
            _memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            if let WasmVal::I32(codec_id) = args[0].clone() {
                ctx.delete_codec(codec_id as usize);
                Ok(WasmVal::I32(0))
            } else {
                Err(TlsError::ParamError)
            }
        }

        match delete_codec_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    fn write_tls(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn write_tls_inner(
            memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            let codec_id = args[0].clone();
            let raw_buf = args[1].clone();
            let raw_len = args[2].clone();
            let tls_buf = args[3].clone();
            let tls_len = args[4].clone();
            let read_num_ptr = args[5].clone();
            let write_num_ptr = args[6].clone();

            if let (
                WasmVal::I32(codec_id),
                WasmVal::I32(raw_buf_ptr),
                WasmVal::I32(raw_len),
                WasmVal::I32(tls_buf_ptr),
                WasmVal::I32(tls_len),
                WasmVal::I32(read_num_ptr),
                WasmVal::I32(write_num_ptr),
            ) = (
                codec_id,
                raw_buf,
                raw_len,
                tls_buf,
                tls_len,
                read_num_ptr,
                write_num_ptr,
            ) {
                let codec = ctx
                    .client_codec
                    .get_mut(codec_id as usize)
                    .ok_or(TlsError::ParamError)?
                    .as_mut()
                    .ok_or(TlsError::ParamError)?;

                let raw_buf;
                let tls_buf;
                unsafe {
                    let raw_buf_ptr = memory
                        .data_pointer_raw(raw_buf_ptr as usize, raw_len as usize)
                        .ok_or(TlsError::ParamError)?;

                    let tls_buf_ptr = memory
                        .data_pointer_mut_raw(tls_buf_ptr as usize, tls_len as usize)
                        .ok_or(TlsError::ParamError)?;

                    raw_buf = std::slice::from_raw_parts(raw_buf_ptr, raw_len as usize);
                    tls_buf = std::slice::from_raw_parts_mut(tls_buf_ptr, tls_len as usize);
                }

                let (r_num, w_num) = codec.write_tls(raw_buf, tls_buf)?;
                memory
                    .write_data((read_num_ptr as usize).into(), r_num as i32)
                    .ok_or(TlsError::ParamError)?;

                memory
                    .write_data((write_num_ptr as usize).into(), w_num as i32)
                    .ok_or(TlsError::ParamError)?;

                Ok(WasmVal::I32(0))
            } else {
                Err(TlsError::ParamError)
            }
        }

        match write_tls_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    fn read_tls(
        memory: &mut Memory,
        ctx: &mut Ctx,
        args: Vec<WasmVal>,
    ) -> Result<Vec<WasmVal>, CoreError> {
        #[inline]
        fn read_tls_inner(
            memory: &mut Memory,
            ctx: &mut Ctx,
            args: Vec<WasmVal>,
        ) -> Result<WasmVal, TlsError> {
            let codec_id = args[0].clone();
            let tls_buf = args[1].clone();
            let tls_len = args[2].clone();
            let raw_buf = args[3].clone();
            let raw_len = args[4].clone();
            let read_num_ptr = args[5].clone();
            let write_num_ptr = args[6].clone();

            if let (
                WasmVal::I32(codec_id),
                WasmVal::I32(raw_buf_ptr),
                WasmVal::I32(raw_len),
                WasmVal::I32(tls_buf_ptr),
                WasmVal::I32(tls_len),
                WasmVal::I32(read_num_ptr),
                WasmVal::I32(write_num_ptr),
            ) = (
                codec_id,
                raw_buf,
                raw_len,
                tls_buf,
                tls_len,
                read_num_ptr,
                write_num_ptr,
            ) {
                let codec = ctx
                    .client_codec
                    .get_mut(codec_id as usize)
                    .ok_or(TlsError::ParamError)?
                    .as_mut()
                    .ok_or(TlsError::ParamError)?;

                let raw_buf;
                let tls_buf;
                unsafe {
                    let raw_buf_ptr = memory
                        .data_pointer_mut_raw(raw_buf_ptr as usize, raw_len as usize)
                        .ok_or(TlsError::ParamError)?;

                    let tls_buf_ptr = memory
                        .data_pointer_raw(tls_buf_ptr as usize, tls_len as usize)
                        .ok_or(TlsError::ParamError)?;

                    raw_buf = std::slice::from_raw_parts_mut(raw_buf_ptr, raw_len as usize);
                    tls_buf = std::slice::from_raw_parts(tls_buf_ptr, tls_len as usize);
                }

                let (r_num, w_num) = codec.read_tls(tls_buf, raw_buf)?;
                memory
                    .write_data((read_num_ptr as usize).into(), r_num as i32)
                    .ok_or(TlsError::ParamError)?;

                memory
                    .write_data((write_num_ptr as usize).into(), w_num as i32)
                    .ok_or(TlsError::ParamError)?;

                Ok(WasmVal::I32(0))
            } else {
                Err(TlsError::ParamError)
            }
        }

        match read_tls_inner(memory, ctx, args) {
            Ok(ok) => Ok(vec![ok]),
            Err(e) => Ok(vec![WasmVal::I32(e.error_code())]),
        }
    }

    pub unsafe extern "C" fn create_module(
        _desc: *const ffi::WasmEdge_ModuleDescriptor,
    ) -> *mut ffi::WasmEdge_ModuleInstanceContext {
        let mut module = crate::core::ImportModule::create("rustls_client", Ctx::new()).unwrap();
        module
            .add_sync_func(
                "default_config",
                (vec![], vec![ValType::I32]),
                default_config,
            )
            .unwrap();

        module
            .add_sync_func(
                "new_codec",
                (
                    vec![ValType::I32, ValType::I32, ValType::I32],
                    vec![ValType::I32],
                ),
                new_client_codec,
            )
            .unwrap();

        module
            .add_sync_func(
                "codec_is_handshaking",
                (vec![ValType::I32], vec![ValType::I32]),
                is_handshaking,
            )
            .unwrap();

        module
            .add_sync_func(
                "codec_wants",
                (vec![ValType::I32], vec![ValType::I32]),
                wants,
            )
            .unwrap();

        module
            .add_sync_func(
                "delete_codec",
                (vec![ValType::I32], vec![ValType::I32]),
                delete_codec,
            )
            .unwrap();

        module
            .add_sync_func(
                "write_tls",
                (
                    vec![
                        ValType::I32, //codec_id
                        ValType::I32, // raw_buf
                        ValType::I32, // raw_buf_len
                        ValType::I32, // tls_buf
                        ValType::I32, // tls_buf_len
                        ValType::I32, // read_num
                        ValType::I32, // write_num
                    ],
                    vec![ValType::I32],
                ),
                write_tls,
            )
            .unwrap();

        module
            .add_sync_func(
                "read_tls",
                (
                    vec![
                        ValType::I32, //codec_id
                        ValType::I32, // tls_buf
                        ValType::I32, // tls_buf_len
                        ValType::I32, // raw_buf
                        ValType::I32, // raw_buf_len
                        ValType::I32, // read_num
                        ValType::I32, // write_num
                    ],
                    vec![ValType::I32],
                ),
                read_tls,
            )
            .unwrap();

        let ctx = module.inner.0;
        std::mem::forget(module);
        ctx
    }
}

const MODULE_DESC: [ffi::WasmEdge_ModuleDescriptor; 1] = [ffi::WasmEdge_ModuleDescriptor {
    Name: "rustls_client\0".as_ptr().cast(),
    Description: "rustls client module\0".as_ptr().cast(),
    Create: Some(wasmedge_client_plugin::create_module),
}];

pub const PLUGIN_DESC: ffi::WasmEdge_PluginDescriptor = ffi::WasmEdge_PluginDescriptor {
    Name: "rustls\0".as_ptr().cast(),
    Description: "rustls plugin\0".as_ptr().cast(),
    APIVersion: ffi::WasmEdge_Plugin_CurrentAPIVersion,
    Version: ffi::WasmEdge_PluginVersionData {
        Major: 0,
        Minor: 0,
        Patch: 1,
        Build: 0,
    },
    ModuleCount: 1,
    ProgramOptionCount: 0,
    ModuleDescriptions: &MODULE_DESC as *const _ as *mut _,
    ProgramOptions: null_mut(),
};

#[export_name = "WasmEdge_Plugin_GetDescriptor"]
pub extern "C" fn plugin_hook() -> *const wasmedge_sys_ffi::WasmEdge_PluginDescriptor {
    &PLUGIN_DESC
}
