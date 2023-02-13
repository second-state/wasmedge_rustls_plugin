#! /bin/sh
bindgen --impl-debug --size_t-is-usize --no-layout-tests  WasmEdge/build/include/api/wasmedge/wasmedge.h --no-prepend-enum-name --dynamic-link-require-all --allowlist-type="WasmEdge.*" --allowlist-var="WasmEdge.*" --allowlist-function="WasmEdge.*" -o src/ffi.rs -- -IWasmEdge/build/include/api/
