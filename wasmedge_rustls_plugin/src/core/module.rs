//! Defines WasmEdge Instance and other relevant types.

use std::os::raw::c_void;

use thiserror::Error;
use wasmedge_sys_ffi as ffi;

use super::{
    instance::function::{FnWrapper, Function},
    types::{ValType, WasmVal},
};
use crate::error::{CoreError, InstanceError};

use super::{instance::memory::Memory, types::WasmEdgeString};

#[derive(Debug, Clone)]
pub struct ConstGlobal {
    pub name: String,
    pub val: WasmVal,
}

#[derive(Debug, Clone)]
pub struct MutGlobal {
    pub name: String,
    pub val: WasmVal,
}

#[derive(Debug, Clone)]
pub enum Global {
    Const(ConstGlobal),
    Mut(MutGlobal),
}

pub(crate) trait AsInnerInstance {
    unsafe fn get_mut_ptr(&self) -> *mut ffi::WasmEdge_ModuleInstanceContext;
}

impl AsInnerInstance for InnerInstance {
    unsafe fn get_mut_ptr(&self) -> *mut ffi::WasmEdge_ModuleInstanceContext {
        self.0
    }
}

#[derive(Debug)]
pub(crate) struct InnerInstance(pub(crate) *mut ffi::WasmEdge_ModuleInstanceContext);
impl Drop for InnerInstance {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ffi::WasmEdge_ModuleInstanceDelete(self.0);
            }
        }
    }
}
unsafe impl Send for InnerInstance {}
unsafe impl Sync for InnerInstance {}

#[derive(Debug)]
pub struct ImportModule<T: Sized + Send> {
    pub(crate) inner: InnerInstance,
    pub name: String,
    pub data: Box<T>,
}

impl<T: Sized + Send> ImportModule<T> {
    pub fn create<S: AsRef<str>>(name: S, data: T) -> Result<Self, InstanceError> {
        let raw_name = WasmEdgeString::new(name.as_ref())?;
        let ctx = unsafe { ffi::WasmEdge_ModuleInstanceCreate(raw_name.as_raw()) };

        match ctx.is_null() {
            true => Err(InstanceError::CreateImportModule),
            false => Ok(Self {
                inner: InnerInstance(ctx),
                name: name.as_ref().to_string(),
                data: Box::new(data),
            }),
        }
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }

    pub fn unpack(self) -> Box<T> {
        self.data
    }
}

pub(crate) unsafe extern "C" fn wrapper_sync_fn<T: Sized + Send>(
    key_ptr: *mut c_void,
    data_ptr: *mut c_void,
    calling_frame_ctx: *const ffi::WasmEdge_CallingFrameContext,
    params: *const ffi::WasmEdge_Value,
    param_len: u32,
    returns: *mut ffi::WasmEdge_Value,
    return_len: u32,
) -> ffi::WasmEdge_Result {
    let cous = || -> Result<(), CoreError> {
        let main_mem_ctx = ffi::WasmEdge_CallingFrameGetMemoryInstance(calling_frame_ctx, 0);
        let mut mem = Memory::from_raw(main_mem_ctx);
        let data_ptr = data_ptr.cast::<T>().as_mut();
        debug_assert!(data_ptr.is_some());
        let data_ptr = data_ptr.unwrap();

        let real_fn: fn(&mut Memory, &mut T, Vec<WasmVal>) -> Result<Vec<WasmVal>, CoreError> =
            std::mem::transmute(key_ptr);

        let input = {
            let raw_input = std::slice::from_raw_parts(params, param_len as usize);
            raw_input
                .iter()
                .map(|r| (*r).into())
                .collect::<Vec<WasmVal>>()
        };
        let v = real_fn(&mut mem, data_ptr, input)?;

        let return_len = return_len as usize;
        let raw_returns = std::slice::from_raw_parts_mut(returns, return_len);

        for (idx, item) in v.into_iter().enumerate() {
            raw_returns[idx] = item.into();
        }
        Ok(())
    };
    match cous() {
        Ok(_) => ffi::WasmEdge_Result { Code: 0x0 },
        Err(e) => e.into(),
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AddFuncError {
    #[error("Found an interior nul byte")]
    NameError(#[from] std::ffi::NulError),
    #[error("Illegal Async Function name ")]
    IllegalName,
    #[error("Fail to create Function instance")]
    FunctionCreate,
}

pub type SyncWasmFn<T> =
    for<'a> fn(&'a mut Memory, &'a mut T, Vec<WasmVal>) -> Result<Vec<WasmVal>, CoreError>;

impl<T: Send + Sized> ImportModule<T> {
    pub unsafe fn add_custom_func(
        &mut self,
        name: &str,
        ty: (Vec<ValType>, Vec<ValType>),
        wrapper_fn: FnWrapper,
        real_fn: *mut c_void,
        data: *mut T,
    ) -> Result<(), AddFuncError> {
        let func_name = WasmEdgeString::new(name)?;
        let func = Function::custom_create(ty, wrapper_fn, real_fn, data.cast())
            .ok_or(AddFuncError::FunctionCreate)?;

        ffi::WasmEdge_ModuleInstanceAddFunction(
            self.inner.0,
            func_name.as_raw(),
            func.inner.0 as *mut _,
        );
        Ok(())
    }

    pub fn add_sync_func(
        &mut self,
        name: &str,
        ty: (Vec<ValType>, Vec<ValType>),
        real_fn: SyncWasmFn<T>,
    ) -> Result<(), AddFuncError> {
        unsafe {
            let data_ptr = self.data.as_mut() as *mut T;
            self.add_custom_func(name, ty, wrapper_sync_fn::<T>, real_fn as *mut _, data_ptr)
        }
    }
}
