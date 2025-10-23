// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ffi;
use std::io::Write;
use std::ptr;
use std::slice;

use boring_sys_vendit::*;
use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;
use log::trace;

use crate::Error;
use crate::Result;
use crate::codec::Decoder;
use crate::tls;
use crate::tls::TlsSessionData;
use crate::tls::boringssl::crypto;
use crate::tls::key;

pub type SslCtx = SSL_CTX;
type Ssl = SSL;
type SslCipher = SSL_CIPHER;
type SslSession = SSL_SESSION;
type X509Store = X509_STORE;
type CryptoBuffer = CRYPTO_BUFFER;
type CryptoBufferPool = CRYPTO_BUFFER_POOL;
type Cbb = CBB;
type CryptoExData = CRYPTO_EX_DATA;

/// Certificate Compression Algorithm IDs from RFC 8879
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CertCompressionAlgorithm {
    /// zlib compression (RFC 1950)
    Zlib = 1,
    /// Brotli compression (RFC 7932)
    Brotli = 2,
    /// Zstandard compression (RFC 8478)
    Zstd = 3,
}

pub type SslEarlyDataReason = ssl_early_data_reason_t;

/// Renegotiation mode for TLS clients. See BoringSSL's `ssl_renegotiate_mode_t`.
pub type SslRenegotiateMode = ssl_renegotiate_mode_t;

/// Called when TLS context is being destroyed.
/// See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ex_data.h.html
unsafe extern "C" fn context_data_free(
    parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _index: c_int,
    arg1: c_long,
    _argp: *mut c_void,
) {
    if parent.is_null() || ptr.is_null() || arg1 != 0 {
        return;
    }

    unsafe {
        // `ptr` is the ALPN data set by `SSL_CTX_set_ex_data`.
        let _ = Box::from_raw(ptr as *mut Vec<Vec<u8>>);
    };
}

lazy_static::lazy_static! {
    /// Boringssl extra data index for tls context.
    pub static ref CONTEXT_DATA_INDEX: c_int = unsafe {
        SSL_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, Some(context_data_free))
    };

    /// Boringssl extra data index for tls session.
    pub static ref SESSION_DATA_INDEX: c_int = unsafe {
        SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
    };
}

static SSL_QUIC_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

/// Rust wrapper of SSL_CTX which holds various configuration and data relevant
/// to SSL/TLS session establishment.
pub(crate) struct Context {
    ctx_raw: *mut SslCtx,
    owned: bool,
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.owned {
            unsafe { SSL_CTX_free(self.as_mut_ptr()) }
        }
    }
}

impl Context {
    /// Create a new TLS context.
    pub fn new() -> Result<Context> {
        unsafe {
            let ctx_raw = SSL_CTX_new(TLS_method());

            let mut ctx = Context {
                ctx_raw,
                owned: true,
            };

            ctx.set_session_callback();
            ctx.set_default_verify_paths()?;
            Ok(ctx)
        }
    }

    /// Create a new TLS context with SSL_CTX.
    /// The caller is responsible for the memory of SSL_CTX when use this function.
    pub fn new_with_ssl_ctx(ssl_ctx: *mut SslCtx) -> Context {
        Self {
            ctx_raw: ssl_ctx,
            owned: false,
        }
    }

    /// Return the mutable pointer of the inner SSL_CTX.
    pub fn as_mut_ptr(&mut self) -> *mut SslCtx {
        self.ctx_raw
    }

    /// Return the const pointer of the inner SSL_CTX.
    pub fn as_ptr(&self) -> *const SslCtx {
        self.ctx_raw
    }

    /// Create a new TLS session.
    pub fn new_session(&self) -> Result<Session> {
        unsafe {
            let ssl = SSL_new(self.as_ptr() as *mut SslCtx);
            Ok(Session::new(ssl))
        }
    }

    /// Specify the locations at which CA certificates for verification purposes are located.
    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let file = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe {
            SSL_CTX_load_verify_locations(self.as_mut_ptr(), file.as_ptr(), std::ptr::null())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "load verify locations from file({:?}) failed",
                file
            ))),
        }
    }

    /// Specify the locations at which CA certificates for verification purposes are located.
    pub fn load_verify_locations_from_directory(&mut self, path: &str) -> Result<()> {
        let path = ffi::CString::new(path)
            .map_err(|e| Error::TlsFail(format!("path name({:?}) format error: {:?}", path, e)))?;
        match unsafe {
            SSL_CTX_load_verify_locations(self.as_mut_ptr(), std::ptr::null(), path.as_ptr())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "load verify locations from path({:?}) failed",
                path
            ))),
        }
    }

    /// Load a certificate chain from file into ctx. The certificates must be in
    /// PEM format and must be sorted starting with the subject's certificate
    /// (actual client or server certificate), followed by intermediate CA
    /// certificates if applicable, and ending at the highest level (root) CA.
    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe { SSL_CTX_use_certificate_chain_file(self.as_mut_ptr(), cstr.as_ptr()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "use certificate chain file({:?}) failed",
                file
            ))),
        }
    }

    /// Add the first private key found in file to ctx.
    pub fn use_private_key_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe { SSL_CTX_use_PrivateKey_file(self.as_mut_ptr(), cstr.as_ptr(), 1) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "use private key file({:?}) failed",
                file
            ))),
        }
    }

    /// Load trust anchors from directory in OpenSSL's hashed directory format.
    #[cfg(not(windows))]
    fn set_default_verify_paths(&mut self) -> Result<()> {
        match unsafe { SSL_CTX_set_default_verify_paths(self.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(
                "set default verify paths failed".to_string(),
            )),
        }
    }

    #[cfg(windows)]
    fn set_default_verify_paths(&mut self) -> Result<()> {
        unsafe {
            // Open system certificate store
            let cstr = ffi::CString::new("Root")
                .map_err(|_| Error::TlsFail("CString::new".to_string()))?;
            let sys_store = winapi::um::wincrypt::CertOpenSystemStoreA(
                0,
                cstr.as_ptr() as winapi::um::winnt::LPCSTR,
            );
            if sys_store.is_null() {
                return Err(Error::TlsFail("open system store".to_string()));
            }

            // Get the certificate store for the current SSLContext
            let crt_store = SSL_CTX_get_cert_store(self.as_mut_ptr());
            if crt_store.is_null() {
                winapi::um::wincrypt::CertCloseStore(sys_store, 0);
                return Err(Error::TlsFail("get cert store".to_string()));
            }

            // Retrieve certificates in the system certificate store and add them
            // to the X509_STORE for the current SSLContext.
            let mut ctx_p =
                winapi::um::wincrypt::CertEnumCertificatesInStore(sys_store, ptr::null());
            while !ctx_p.is_null() {
                let mut in_p = (*ctx_p).pbCertEncoded as *const u8;
                let cert = d2i_X509(ptr::null_mut(), &mut in_p, (*ctx_p).cbCertEncoded as i32);
                if !cert.is_null() {
                    X509_STORE_add_cert(crt_store, cert);
                    X509_free(cert);
                }
                ctx_p = winapi::um::wincrypt::CertEnumCertificatesInStore(sys_store, ctx_p);
            }

            winapi::um::wincrypt::CertFreeCertificateContext(ctx_p);
            winapi::um::wincrypt::CertCloseStore(sys_store, 0);
        }

        Ok(())
    }

    /// Set the callback function that is called whenever a new session was negotiated.
    pub fn set_session_callback(&mut self) {
        unsafe {
            SSL_CTX_set_session_cache_mode(
                self.as_mut_ptr(),
                0x0001, // SSL_SESS_CACHE_CLIENT
            );

            SSL_CTX_sess_set_new_cb(self.as_mut_ptr(), Some(new_session));
        };
    }

    /// Configure certificate verification behavior.
    /// True: make server certificate errors fatal.
    /// False: verify the server certificate but not make errors fatal.
    pub fn set_verify(&mut self, verify: bool) {
        let mode = i32::from(verify);

        unsafe {
            SSL_CTX_set_verify(self.as_mut_ptr(), mode, None);
        }
    }

    /// Set the TLS key logging callback. This callback is called whenever TLS
    /// key material is generated or received, in order to allow applications
    /// to store this keying material for debugging purposes.
    pub fn enable_keylog(&mut self) {
        unsafe {
            SSL_CTX_set_keylog_callback(self.as_mut_ptr(), Some(keylog));
        }
    }

    /// Set the list of protocols available to be negotiated for the client, or
    /// Set the application callback cb used by a server to select which
    /// protocol to use for the incoming connection.
    pub fn set_alpn(&mut self, v: Vec<Vec<u8>>) -> Result<()> {
        let mut protos: Vec<u8> = Vec::new();
        for proto in &v {
            protos.push(proto.len() as u8);
            protos.extend_from_slice(proto);
        }

        let v = Box::new(v);
        unsafe {
            SSL_CTX_set_ex_data(
                self.as_mut_ptr(),
                *CONTEXT_DATA_INDEX,
                Box::into_raw(v) as *mut c_void,
            );
        }

        unsafe {
            SSL_CTX_set_alpn_select_cb(self.as_mut_ptr(), Some(select_alpn), ptr::null_mut());
        }

        // SSL_CTX_set_alpn_protos() returns 0 on success.
        match unsafe { SSL_CTX_set_alpn_protos(self.as_mut_ptr(), protos.as_ptr(), protos.len()) } {
            0 => Ok(()),
            _ => Err(Error::TlsFail("SSL set alpn failed".to_string())),
        }
    }

    /// Set ctx's session ticket key material
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        match unsafe {
            SSL_CTX_set_tlsext_ticket_keys(
                self.as_mut_ptr(),
                key.as_ptr() as *const libc::c_void,
                key.len(),
            )
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("set ticket key failed".to_string())),
        }
    }

    /// Set whether early data is allowed to be used with resumptions using ctx.
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        let enabled = i32::from(enabled);

        unsafe {
            SSL_CTX_set_early_data_enabled(self.as_mut_ptr(), enabled);
        }
    }

    /// Set the lifetime, in seconds, of TLS 1.3 sessions created in ctx to timeout.
    pub fn set_session_psk_dhe_timeout(&mut self, timeout: u32) {
        unsafe {
            SSL_CTX_set_session_psk_dhe_timeout(self.as_mut_ptr(), timeout);
        }
    }

    /// Enable certificate compression for the specified algorithm.
    /// Returns Ok(()) on success, Err on failure.
    pub fn add_cert_compression_alg(&mut self, algorithm: CertCompressionAlgorithm) -> Result<()> {
        let (compress_func, decompress_func) = match algorithm {
            CertCompressionAlgorithm::Zlib => (
                cert_compress_zlib as extern "C" fn(*mut Ssl, *mut Cbb, *const u8, usize) -> c_int,
                cert_decompress_zlib
                    as extern "C" fn(
                        *mut Ssl,
                        *mut *mut CryptoBuffer,
                        usize,
                        *const u8,
                        usize,
                    ) -> c_int,
            ),
            CertCompressionAlgorithm::Brotli => (
                cert_compress_brotli
                    as extern "C" fn(*mut Ssl, *mut Cbb, *const u8, usize) -> c_int,
                cert_decompress_brotli
                    as extern "C" fn(
                        *mut Ssl,
                        *mut *mut CryptoBuffer,
                        usize,
                        *const u8,
                        usize,
                    ) -> c_int,
            ),
            CertCompressionAlgorithm::Zstd => {
                return Err(Error::TlsFail(
                    "Zstd compression not implemented yet".to_string(),
                ));
            }
        };

        match unsafe {
            SSL_CTX_add_cert_compression_alg(
                self.as_mut_ptr(),
                algorithm as u16,
                Some(compress_func),
                Some(decompress_func),
            )
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "Failed to add certificate compression algorithm: {:?}",
                algorithm
            ))),
        }
    }
}

fn get_ctx_data_from_ptr<'a, T>(ptr: *mut SslCtx, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_CTX_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

unsafe impl std::marker::Send for Context {}

unsafe impl std::marker::Sync for Context {}

/// Rust wrapper of SSL which is needed to hold the data for a TLS/SSL connection.
/// It inherits the settings of the underlying context ctx.
pub struct Session {
    /// The raw pointer to the SSL object.
    ptr: *mut Ssl,

    /// SSL_process_quic_post_handshake should be called when whenever
    /// SSL_provide_quic_data is called to process the provided data.
    provided_data_outstanding: bool,
}

impl Session {
    fn new(ptr: *mut Ssl) -> Session {
        Session {
            ptr,
            provided_data_outstanding: false,
        }
    }

    /// Obtain result code for TLS/SSL I/O operation.
    pub fn get_error(&self, ret_code: c_int) -> c_int {
        unsafe { SSL_get_error(self.as_ptr(), ret_code) }
    }

    pub fn init(&mut self) -> Result<()> {
        self.set_connect_state();

        const TLS1_3_VERSION: u16 = 0x0304;
        const SSL_GROUP_X25519_MLKEM768: u16 = 0x11ec;

        self.set_min_proto_version(TLS1_3_VERSION);
        self.set_max_proto_version(TLS1_3_VERSION);
        self.set_renegotiate_mode(SslRenegotiateMode::ssl_renegotiate_explicit);
        self.set_shed_handshake_config(true);
        self.set_encrypted_client_hello(true);
        self.set_permute_extensions(true);
        self.set_quic_method()?;
        self.set_quic_early_data_context(b"quic")?;
        self.set_quiet_shutdown(true);
        self.set_alps_use_new_codepoint(true);
        self.set_curves("X25519MLKEM768:X25519:P-256:P-384")?;

        self.set_group_ids(&[SSL_GROUP_X25519_MLKEM768, 29, 23, 24])?;
        self.set_client_key_shares(&[SSL_GROUP_X25519_MLKEM768, 29, 23, 24])?;
        self.add_application_settings(b"h3", &[])?;
        self.set_sigalgs("ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512")?;

        Ok(())
    }

    pub fn set_curves(&mut self, curves: &str) -> Result<()> {
        let cstr = ffi::CString::new(curves)
            .map_err(|_| Error::TlsFail("curves format error".to_string()))?;
        unsafe {
            match SSL_CTX_set1_curves_list(SSL_get_SSL_CTX(self.as_ptr()), cstr.as_ptr()) {
                1 => Ok(()),
                _ => Err(Error::TlsFail("SSL set curves failed".to_string())),
            }
        }
    }

    pub fn set_sigalgs(&mut self, sigalgs: &str) -> Result<()> {
        let cstr = ffi::CString::new(sigalgs)
            .map_err(|_| Error::TlsFail("sigalgs format error".to_string()))?;
        match unsafe { SSL_CTX_set1_sigalgs_list(SSL_get_SSL_CTX(self.as_ptr()), cstr.as_ptr()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set sigalgs failed".to_string())),
        }
    }

    pub fn set_alps_use_new_codepoint(&mut self, use_new: bool) {
        unsafe {
            SSL_set_alps_use_new_codepoint(self.as_mut_ptr(), i32::from(use_new));
        }
    }

    pub fn set_client_key_shares(&mut self, groups: &[u16]) -> Result<()> {
        unsafe {
            match SSL_set1_client_key_shares(self.as_mut_ptr(), groups.as_ptr(), groups.len()) {
                1 => Ok(()),
                _ => Err(Error::TlsFail(
                    "SSL set client key shares failed".to_string(),
                )),
            }
        }
    }

    pub fn set_group_ids(&mut self, groups: &[u16]) -> Result<()> {
        unsafe {
            match SSL_set1_group_ids(self.as_mut_ptr(), groups.as_ptr(), groups.len()) {
                1 => Ok(()),
                _ => Err(Error::TlsFail("SSL set group ids failed".to_string())),
            }
        }
    }

    pub fn add_application_settings(&mut self, proto: &[u8], settings: &[u8]) -> Result<()> {
        unsafe {
            match SSL_add_application_settings(
                self.as_mut_ptr(),
                proto.as_ptr(),
                proto.len(),
                settings.as_ptr(),
                settings.len(),
            ) {
                1 => Ok(()),
                _ => Err(Error::TlsFail(
                    "SSL add application settings failed".to_string(),
                )),
            }
        }
    }

    pub fn enable_signed_cert_timestamps(&mut self) {
        unsafe {
            SSL_enable_signed_cert_timestamps(self.as_mut_ptr());
        }
    }

    pub fn enable_ocsp_stapling(&mut self) {
        unsafe {
            SSL_enable_ocsp_stapling(self.as_mut_ptr());
        }
    }

    pub fn set_renegotiate_mode(&mut self, mode: SslRenegotiateMode) {
        unsafe {
            SSL_set_renegotiate_mode(self.as_mut_ptr(), mode);
        }
    }

    pub fn set_shed_handshake_config(&mut self, enabled: bool) {
        unsafe {
            SSL_set_shed_handshake_config(self.as_mut_ptr(), i32::from(enabled));
        }
    }

    pub fn set_encrypted_client_hello(&mut self, enabled: bool) {
        unsafe {
            SSL_set_enable_ech_grease(self.as_mut_ptr(), i32::from(enabled));
        }
    }

    pub fn set_permute_extensions(&mut self, enabled: bool) {
        unsafe {
            SSL_set_permute_extensions(self.as_mut_ptr(), i32::from(enabled));
        }
    }

    /// Set ssl to work in client or server mode.
    pub fn set_connect_state(&mut self) {
        unsafe {
            SSL_set_connect_state(self.as_mut_ptr());
        }
    }

    /// Store arbitrary user data into the or SSL object. The user must supply
    /// a unique index.
    pub fn set_ex_data<T>(&mut self, idx: c_int, data: *const T) -> Result<()> {
        match unsafe {
            let ptr = data as *mut libc::c_void;
            SSL_set_ex_data(self.as_mut_ptr(), idx, ptr)
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set extra data failed".to_string())),
        }
    }

    /// Configure the QUIC callback functions.
    pub fn set_quic_method(&mut self) -> Result<()> {
        match unsafe { SSL_set_quic_method(self.as_mut_ptr(), &SSL_QUIC_METHOD) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set quic method failed".to_string())),
        }
    }

    /// Configure a context string in QUIC servers for accepting early data.
    /// If a resumption connection offers early data, the server will check if
    /// the value matches that of the connection which minted the ticket. If
    /// not, resumption still succeeds but early data is rejected.
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        match unsafe {
            SSL_set_quic_early_data_context(self.as_mut_ptr(), context.as_ptr(), context.len())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(
                "SSL set quic early data context failed".to_string(),
            )),
        }
    }

    /// Set the minimum protocol version for ssl to version.
    pub fn set_min_proto_version(&mut self, version: u16) {
        unsafe {
            SSL_set_min_proto_version(self.as_mut_ptr(), version);
        }
    }

    /// Set the maximum protocol version for ssl to version.
    pub fn set_max_proto_version(&mut self, version: u16) {
        unsafe {
            SSL_set_max_proto_version(self.as_mut_ptr(), version);
        }
    }

    /// Set quiet shutdown on ssl. If enabled, SSL_shutdown will not send a
    /// close_notify alert or wait for one from the peer.
    pub fn set_quiet_shutdown(&mut self, mode: bool) {
        unsafe { SSL_set_quiet_shutdown(self.as_mut_ptr(), i32::from(mode)) }
    }

    /// Configure ssl to advertise name in the server_name extension for client.
    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name)
            .map_err(|_| Error::TlsFail("host name format error".to_string()))?;
        let rc = unsafe { SSL_set_tlsext_host_name(self.as_mut_ptr(), cstr.as_ptr()) };
        self.map_result_ssl(rc, None)?;

        // Retrieve an internal pointer to the verification parameters for ssl
        let param = unsafe { SSL_get0_param(self.as_mut_ptr()) };

        // Set the expected DNS hostname to name clearing any previously specified hostname.
        match unsafe { X509_VERIFY_PARAM_set1_host(param, cstr.as_ptr(), name.len()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "SSL set host name({:?}) failed",
                name
            ))),
        }
    }

    /// Set a callback that is called to select a certificate.
    pub fn set_cert_cb(&mut self) {
        unsafe { SSL_set_cert_cb(self.as_mut_ptr(), Some(select_cert), std::ptr::null_mut()) }
    }

    /// Configure ssl to send params in the quic_transport_parameters extension
    /// in either the ClientHello or EncryptedExtensions handshake message.
    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        let rc =
            unsafe { SSL_set_quic_transport_params(self.as_mut_ptr(), buf.as_ptr(), buf.len()) };
        self.map_result_ssl(rc, None)
    }

    /// Return the value of the quic_transport_parameters extension sent by the
    /// peer.
    pub fn quic_transport_params(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        unsafe {
            SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    /// Return the selected protocol.
    pub fn alpn_protocol(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: u32 = 0;

        unsafe {
            SSL_get0_alpn_selected(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts(ptr, len as usize) }
    }

    /// Return the server name.
    pub fn server_name(&self) -> Option<&str> {
        let s = unsafe {
            let ptr = SSL_get_servername(
                self.as_ptr(),
                0, // TLSEXT_NAMETYPE_host_name
            );

            if ptr.is_null() {
                return None;
            }
            ffi::CStr::from_ptr(ptr)
        };

        s.to_str().ok()
    }

    /// Set session to be used when the TLS/SSL connection is to be established.
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        let ctx = unsafe { SSL_get_SSL_CTX(self.as_ptr()) };
        if ctx.is_null() {
            return Err(Error::TlsFail("SSL context is null".to_string()));
        }

        let session = unsafe { SSL_SESSION_from_bytes(session.as_ptr(), session.len(), ctx) };
        if session.is_null() {
            return Err(Error::TlsFail("SSL session is null".to_string()));
        }

        match unsafe {
            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);
            rc
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set session failed".to_string())),
        }
    }

    /// Provide data from QUIC at a particular encryption level level.
    pub fn provide_data(&mut self, level: tls::Level, buf: &[u8]) -> Result<()> {
        self.provided_data_outstanding = true;
        let lvl = match level {
            tls::Level::Initial => ssl_encryption_level_t::ssl_encryption_initial,
            tls::Level::ZeroRTT => ssl_encryption_level_t::ssl_encryption_early_data,
            tls::Level::Handshake => ssl_encryption_level_t::ssl_encryption_handshake,
            tls::Level::OneRTT => ssl_encryption_level_t::ssl_encryption_application,
        };
        let rc = unsafe { SSL_provide_quic_data(self.as_mut_ptr(), lvl, buf.as_ptr(), buf.len()) };
        self.map_result_ssl(rc, None)
    }

    /// Continue the current handshake.
    pub fn do_handshake(&mut self, session_data: &mut tls::TlsSessionData) -> Result<()> {
        self.set_ex_data(*SESSION_DATA_INDEX, session_data)?;
        let rc = unsafe { SSL_do_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<tls::TlsSessionData>(*SESSION_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(session_data, rc);
        self.map_result_ssl(rc, Some(session_data))
    }

    /// Processes any data that QUIC has provided after the handshake has
    /// completed. This includes NewSessionTicket messages sent by the server.
    pub fn process_post_handshake(&mut self, session_data: &mut tls::TlsSessionData) -> Result<()> {
        // If SSL_provide_quic_data hasn't been called since we last called
        // SSL_process_quic_post_handshake, then there's nothing to do.
        if !self.provided_data_outstanding {
            return Ok(());
        }
        self.provided_data_outstanding = false;

        self.set_ex_data(*SESSION_DATA_INDEX, session_data)?;
        let rc = unsafe { SSL_process_quic_post_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<tls::TlsSessionData>(*SESSION_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(session_data, rc);
        self.map_result_ssl(rc, Some(session_data))
    }

    /// Resets ssl after an early data reject. All 0-RTT state is discarded,
    /// including any pending SSL_write calls. The caller should treat ssl
    /// as a logically fresh connection.
    pub fn reset_early_data_reject(&mut self) {
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    /// Return the current write encryption level.
    pub fn write_level(&self) -> tls::Level {
        let lvl = unsafe { SSL_quic_write_level(self.as_ptr()) };
        match lvl {
            ssl_encryption_level_t::ssl_encryption_initial => tls::Level::Initial,
            ssl_encryption_level_t::ssl_encryption_early_data => tls::Level::ZeroRTT,
            ssl_encryption_level_t::ssl_encryption_handshake => tls::Level::Handshake,
            ssl_encryption_level_t::ssl_encryption_application => tls::Level::OneRTT,
            _ => tls::Level::Initial,
        }
    }

    /// Return the cipher suite used by ssl.
    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let cipher = map_result_ptr(unsafe { SSL_get_current_cipher(self.as_ptr()) });
        get_cipher_from_ptr(cipher.ok()?).ok()
    }

    /// Return a human-readable name for the curve used by ssl.
    pub fn curve(&self) -> Option<String> {
        let curve = unsafe {
            let curve_id = SSL_get_curve_id(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_get_curve_name(curve_id);
            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,
                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    /// Returns a human-readable name for signature algorithm used by the peer.
    pub fn peer_sign_algor(&self) -> Option<String> {
        let sigalg = unsafe {
            let sigalg_id = SSL_get_peer_signature_algorithm(self.as_ptr());
            if sigalg_id == 0 {
                return None;
            }

            let sigalg_name = SSL_get_signature_algorithm_name(sigalg_id, 1);
            match ffi::CStr::from_ptr(sigalg_name).to_str() {
                Ok(v) => v,
                Err(_) => return None,
            }
        };

        Some(sigalg.to_string())
    }

    /// Return the peer's certificate chain.
    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let cert_chain = unsafe {
            let chain_ptr = SSL_get0_peer_certificates(self.as_ptr());
            if chain_ptr.is_null() {
                return None;
            }

            let stack = chain_ptr as *const OPENSSL_STACK;
            let num = OPENSSL_sk_num(stack);
            if num == 0 {
                return None;
            }

            let mut cert_chain = vec![];
            for i in 0..num {
                let buf_ptr = OPENSSL_sk_value(stack, i) as *const CryptoBuffer;
                let buffer = map_result_ptr(buf_ptr).ok()?;
                let out_len = CRYPTO_BUFFER_len(buffer);
                if out_len == 0 {
                    return None;
                }

                let out = CRYPTO_BUFFER_data(buffer);
                let slice = slice::from_raw_parts(out, out_len);
                cert_chain.push(slice);
            }
            cert_chain
        };

        Some(cert_chain)
    }

    /// Return the peer's certificate.
    pub fn peer_cert(&self) -> Option<&[u8]> {
        let peer_cert = unsafe {
            let chain_ptr = SSL_get0_peer_certificates(self.as_ptr());
            if chain_ptr.is_null() {
                return None;
            }
            let stack = chain_ptr as *const OPENSSL_STACK;
            if OPENSSL_sk_num(stack) == 0 {
                return None;
            }

            let buf_ptr = OPENSSL_sk_value(stack, 0) as *const CryptoBuffer;
            let buffer = map_result_ptr(buf_ptr).ok()?;
            let out_len = CRYPTO_BUFFER_len(buffer);
            if out_len == 0 {
                return None;
            }

            let out = CRYPTO_BUFFER_data(buffer);
            slice::from_raw_parts(out, out_len)
        };

        Some(peer_cert)
    }

    pub fn early_data_reason(&self) -> SslEarlyDataReason {
        unsafe { SSL_get_early_data_reason(self.as_ptr()) }
    }

    pub fn early_data_reason_string(&self) -> Result<Option<&str>> {
        let reason = unsafe {
            let reason = SSL_early_data_reason_string(SSL_get_early_data_reason(self.as_ptr()));
            match ffi::CStr::from_ptr(reason).to_str() {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::TlsFail(format!(
                        "early data reason format error {:?}",
                        e
                    )));
                }
            }
        };

        Ok(Some(reason))
    }

    /// Return true if ssl has a completed handshake.
    pub fn is_completed(&self) -> bool {
        unsafe { SSL_in_init(self.as_ptr()) == 0 }
    }

    /// Return true if ssl performed an abbreviated handshake.
    pub fn is_resumed(&self) -> bool {
        unsafe { SSL_session_reused(self.as_ptr()) == 1 }
    }

    /// Return true if ssl has a pending handshake that has progressed enough
    /// to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }

    /// Resets ssl to allow another connection.
    pub fn clear(&mut self) -> Result<()> {
        let rc = unsafe { SSL_clear(self.as_mut_ptr()) };
        self.map_result_ssl(rc, None)
    }

    fn as_ptr(&self) -> *const Ssl {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut Ssl {
        self.ptr
    }

    /// Convert SSL error.
    fn map_result_ssl(
        &mut self,
        bssl_result: c_int,
        session_data: Option<&mut tls::TlsSessionData>,
    ) -> Result<()> {
        match bssl_result {
            1 => Ok(()),

            _ => {
                let ssl_err = self.get_error(bssl_result);
                match ssl_err {
                    // SSL_ERROR_SSL
                    1 => {
                        let ssl_err = get_ssl_error()?;
                        trace!("SSL error: {}", ssl_err);
                        Err(Error::TlsFail(format!("SSL error: {}", ssl_err)))
                    }

                    // SSL_ERROR_WANT_READ
                    2 => Err(Error::Done),

                    // SSL_ERROR_WANT_WRITE
                    3 => Err(Error::Done),

                    // SSL_ERROR_WANT_X509_LOOKUP
                    4 => Err(Error::Done),

                    // SSL_ERROR_SYSCALL
                    5 => Err(Error::TlsFail("SSL error, syscall".to_string())),

                    // SSL_ERROR_PENDING_SESSION
                    11 => Err(Error::Done),

                    // SSL_ERROR_PENDING_CERTIFICATE
                    12 => Err(Error::Done),

                    // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
                    13 => Err(Error::Done),

                    // SSL_ERROR_PENDING_TICKET
                    14 => Err(Error::Done),

                    // SSL_ERROR_EARLY_DATA_REJECTED
                    15 => {
                        self.reset_early_data_reject();
                        if let Some(session_data) = session_data {
                            trace!("{} early data rejected", session_data.trace_id);
                            session_data.early_data_rejected = true;
                        }
                        Err(Error::Done)
                    }

                    // SSL_ERROR_WANT_CERTIFICATE_VERIFY
                    16 => Err(Error::Done),

                    _ => Err(Error::TlsFail("SSL error, unknown".to_string())),
                }
            }
        }
    }

    fn set_transport_error(&mut self, session_data: &mut tls::TlsSessionData, bssl_result: c_int) {
        if self.get_error(bssl_result) == 1 {
            // SSL_ERROR_SSL error.
            // See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get_error
            if session_data.error.is_none() {
                session_data.error = Some(tls::TlsError {
                    error_code: 0x01,
                    reason: Vec::new(),
                })
            }
        }
    }
}

unsafe impl std::marker::Send for Session {}

unsafe impl std::marker::Sync for Session {}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { SSL_free(self.as_mut_ptr()) }
    }
}

fn get_sess_data_from_ptr<'a, T>(ptr: *mut Ssl, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

fn get_cipher_from_ptr(cipher: *const SslCipher) -> Result<crypto::Algorithm> {
    let cipher_id = unsafe { SSL_CIPHER_get_id(cipher) };

    let algor = match cipher_id {
        0x0300_1301 => crypto::Algorithm::Aes128Gcm,
        0x0300_1302 => crypto::Algorithm::Aes256Gcm,
        0x0300_1303 => crypto::Algorithm::ChaCha20Poly1305,
        _ => return Err(Error::TlsFail("unsupported cipher".to_string())),
    };

    Ok(algor)
}

/// set_read_secret configures the read secret and cipher suite for the given
/// encryption level. It returns one on success and zero to terminate the
/// handshake with an error. It will be called at most once per encryption
/// level.
extern "C" fn set_read_secret(
    ssl: *mut Ssl,
    level: ssl_encryption_level_t,
    cipher: *const SslCipher,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let level = match level {
        ssl_encryption_level_t::ssl_encryption_initial => tls::Level::Initial,
        ssl_encryption_level_t::ssl_encryption_early_data => tls::Level::ZeroRTT,
        ssl_encryption_level_t::ssl_encryption_handshake => tls::Level::Handshake,
        ssl_encryption_level_t::ssl_encryption_application => tls::Level::OneRTT,
        _ => tls::Level::Initial,
    };
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} set read secret level {:?}",
        session_data.trace_id, level
    );

    let keys = &mut session_data.key_collection[level];

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if level != tls::Level::ZeroRTT {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let open = match crypto::Open::new_with_secret(aead, secret.to_vec()) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        keys.open = Some(open);
    }

    1
}

/// set_write_secret configures the write secret and cipher suite for the given
/// encryption level. It will be called at most once per encryption level.
extern "C" fn set_write_secret(
    ssl: *mut Ssl,
    level: ssl_encryption_level_t,
    cipher: *const SslCipher,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let level = match level {
        ssl_encryption_level_t::ssl_encryption_initial => tls::Level::Initial,
        ssl_encryption_level_t::ssl_encryption_early_data => tls::Level::ZeroRTT,
        ssl_encryption_level_t::ssl_encryption_handshake => tls::Level::Handshake,
        ssl_encryption_level_t::ssl_encryption_application => tls::Level::OneRTT,
        _ => tls::Level::Initial,
    };
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} set write secret level {:?}",
        session_data.trace_id, level
    );

    let keys = &mut session_data.key_collection[level];

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if level != tls::Level::ZeroRTT {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let seal = match crypto::Seal::new_with_secret(aead, secret.to_vec()) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        keys.seal = Some(seal);
    }

    1
}

/// add_handshake_data adds handshake data to the current flight at the given
/// encryption level. It returns one on success and zero on error.
extern "C" fn add_handshake_data(
    ssl: *mut Ssl,
    level: ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    let level = match level {
        ssl_encryption_level_t::ssl_encryption_initial => tls::Level::Initial,
        ssl_encryption_level_t::ssl_encryption_early_data => tls::Level::ZeroRTT,
        ssl_encryption_level_t::ssl_encryption_handshake => tls::Level::Handshake,
        ssl_encryption_level_t::ssl_encryption_application => tls::Level::OneRTT,
        _ => tls::Level::Initial,
    };
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} write message level {:?} len {}",
        session_data.trace_id, level, len
    );

    let buf = unsafe { slice::from_raw_parts(data, len) };
    if session_data.write_method.is_none()
        || (session_data.write_method.as_mut().unwrap())(level, buf).is_err()
    {
        return 0;
    }

    1
}

/// flush_flight is called when the current flight is complete and should be
/// written to the transport.
/// Nothing is done since the crypto data is sent separately, see try_write_crypto_frame.
extern "C" fn flush_flight(_ssl: *mut Ssl) -> c_int {
    1
}

/// send_alert sends a fatal alert at the specified encryption level. It
/// returns one on success and zero on error.
extern "C" fn send_alert(ssl: *mut Ssl, level: ssl_encryption_level_t, alert: u8) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} send alert level {:?} alert {:x}",
        session_data.trace_id,
        match level {
            ssl_encryption_level_t::ssl_encryption_initial => tls::Level::Initial,
            ssl_encryption_level_t::ssl_encryption_early_data => tls::Level::ZeroRTT,
            ssl_encryption_level_t::ssl_encryption_handshake => tls::Level::Handshake,
            ssl_encryption_level_t::ssl_encryption_application => tls::Level::OneRTT,
            _ => tls::Level::Initial,
        },
        alert
    );

    const TLS_ALERT_ERROR: u64 = 0x100;
    let error: u64 = TLS_ALERT_ERROR + u64::from(alert);
    session_data.error = Some(tls::TlsError {
        error_code: error,
        reason: Vec::new(),
    });

    1
}

/// A callback to log key material. This is intended for debugging use with
/// tools like Wireshark. The cb function should log line followed by a
/// newline, synchronizing with any concurrent access to the log.
///
/// The output is NSS key log format which is described in:
/// https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format.
extern "C" fn keylog(ssl: *const Ssl, line: *const c_char) {
    let session_data =
        match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl as *mut Ssl, *SESSION_DATA_INDEX) {
            Some(v) => v,
            None => return,
        };

    if let Some(keylog) = &mut session_data.keylog {
        let data = unsafe { ffi::CStr::from_ptr(line).to_bytes() };

        let mut full_line = Vec::with_capacity(data.len() + 1);
        full_line.extend_from_slice(data);
        full_line.push(b'\n');

        keylog.write_all(&full_line[..]).ok();
    }
}

/// A callback function that is called during ClientHello processing in order to
/// select an ALPN protocol from the client's list of offered protocols.
extern "C" fn select_alpn(
    ssl: *mut Ssl,
    out: *mut *const u8,
    out_len: *mut u8,
    inp: *const u8,
    in_len: c_uint,
    _arg: *mut c_void,
) -> c_int {
    // Get customized session data.
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 3, // SSL_TLSEXT_ERR_NOACK
    };

    // Get customized context data.
    let ctx = unsafe { SSL_get_SSL_CTX(ssl) };
    let application_protos = match get_ctx_data_from_ptr::<Vec<Vec<u8>>>(ctx, *CONTEXT_DATA_INDEX) {
        Some(v) => v,
        None => return 3, // SSL_TLSEXT_ERR_NOACK
    };

    if application_protos.is_empty() {
        return 3; // SSL_TLSEXT_ERR_NOACK
    }

    // Select an ALPN protocol.
    let mut protos = unsafe { slice::from_raw_parts(inp, in_len as usize) };
    while let Ok(proto) = protos.read_with_u8_length() {
        let found = application_protos.iter().any(|expected| {
            trace!(
                "{} peer ALPN {:?} expected {:?}",
                session_data.trace_id,
                std::str::from_utf8(proto.as_ref()),
                std::str::from_utf8(expected.as_slice())
            );

            if expected.len() == proto.len() && expected.as_slice() == proto.as_slice() {
                unsafe {
                    *out = expected.as_slice().as_ptr();
                    *out_len = expected.len() as u8;
                }
                return true;
            }

            false
        });

        if found {
            return 0; // SSL_TLSEXT_ERR_OK
        }
    }

    3 // SSL_TLSEXT_ERR_NOACK
}

/// A callback function that is called after extensions have been processed, but before the
/// resumption decision has been made.
extern "C" fn select_cert(ssl: *mut Ssl, _arg: *mut c_void) -> c_int {
    // Get customized session data.
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    // Get server name.
    let server_name = unsafe {
        let ptr = SSL_get_servername(
            ssl, 0, // TLSEXT_NAMETYPE_host_name
        );
        if ptr.is_null() {
            trace!("{} no server name", session_data.trace_id);
            return 1;
        }
        ffi::CStr::from_ptr(ptr)
    };

    let server_name = server_name.to_str();
    if server_name.is_err() {
        trace!("{} server name invalid", session_data.trace_id);
        return 1;
    }
    let server_name = server_name.unwrap();

    trace!("{} select cert for {}", session_data.trace_id, server_name);
    if let Some(config_selector) = &session_data.conf_selector {
        // Select customized tls config based on the server name.
        let tls_config = config_selector.select(server_name);
        if tls_config.is_none() {
            trace!(
                "{} select cert for {} failed.",
                session_data.trace_id, server_name
            );
            return 0;
        }

        // Apply the customized tls config for the SSL connection.
        let tls_ctx = &tls_config.unwrap().tls_ctx;
        let ssl_ctx = unsafe { SSL_set_SSL_CTX(ssl, tls_ctx.ctx_raw) };
        if ssl_ctx.is_null() {
            trace!("{} set SSL_CTX failed", session_data.trace_id);
            return 0;
        }
    }

    1
}

/// A callback to be called when a new session is established and ready to be cached.
extern "C" fn new_session(ssl: *mut Ssl, ssl_session: *mut SslSession) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    let session = Session::new(ssl);
    let peer_params = session.quic_transport_params();

    // Get SSL session.
    let session_bytes = unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        if SSL_SESSION_to_bytes(ssl_session, &mut out, &mut out_len) == 0 {
            return 0;
        }

        let session_bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        OPENSSL_free(out as *mut c_void);
        session_bytes
    };

    let mut buffer = Vec::with_capacity(8 + peer_params.len() + 8 + session_bytes.len());

    // Encode SSL session data.
    let session_bytes_len = session_bytes.len() as u64;
    if buffer.write(&session_bytes_len.to_be_bytes()).is_err() {
        std::mem::forget(session);
        return 0;
    }
    if buffer.write(&session_bytes).is_err() {
        std::mem::forget(session);
        return 0;
    }

    // Encode peer transport parameters.
    let peer_params_len = peer_params.len() as u64;
    if buffer.write(&peer_params_len.to_be_bytes()).is_err() {
        std::mem::forget(session);
        return 0;
    }
    if buffer.write(peer_params).is_err() {
        std::mem::forget(session);
        return 0;
    }

    session_data.session = Some(buffer);

    std::mem::forget(session);
    0
}

/// Certificate compression callback for zlib algorithm
extern "C" fn cert_compress_zlib(
    _ssl: *mut Ssl,
    out: *mut Cbb,
    in_data: *const u8,
    in_len: usize,
) -> c_int {
    use std::io::Write;

    let input = unsafe { std::slice::from_raw_parts(in_data, in_len) };
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());

    if encoder.write_all(input).is_err() {
        return 0;
    }

    let compressed = match encoder.finish() {
        Ok(data) => data,
        Err(_) => return 0,
    };

    // Add compressed data to CBB
    match unsafe { CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) } {
        1 => 1,
        _ => 0,
    }
}

/// Certificate decompression callback for zlib algorithm  
extern "C" fn cert_decompress_zlib(
    _ssl: *mut Ssl,
    out: *mut *mut CryptoBuffer,
    uncompressed_len: usize,
    in_data: *const u8,
    in_len: usize,
) -> c_int {
    use std::io::Read;

    let compressed = unsafe { std::slice::from_raw_parts(in_data, in_len) };
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut decompressed = vec![0u8; uncompressed_len];

    match decoder.read_exact(&mut decompressed) {
        Ok(()) => {
            let buffer = unsafe {
                CRYPTO_BUFFER_new(
                    decompressed.as_ptr(),
                    decompressed.len(),
                    std::ptr::null_mut(),
                )
            };
            if buffer.is_null() {
                return 0;
            }
            unsafe {
                *out = buffer;
            }
            1
        }
        Err(_) => 0,
    }
}

/// Certificate compression callback for brotli algorithm
extern "C" fn cert_compress_brotli(
    _ssl: *mut Ssl,
    out: *mut Cbb,
    in_data: *const u8,
    in_len: usize,
) -> c_int {
    use std::io::Write;

    let input = unsafe { std::slice::from_raw_parts(in_data, in_len) };
    let mut compressed = Vec::new();

    let mut encoder = brotli::CompressorWriter::new(
        &mut compressed,
        4096, // buffer size
        11,   // quality (max compression)
        22,   // window size
    );

    if encoder.write_all(input).is_err() {
        return 0;
    }

    if encoder.flush().is_err() {
        return 0;
    }

    drop(encoder);

    // Add compressed data to CBB
    match unsafe { CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) } {
        1 => 1,
        _ => 0,
    }
}

/// Certificate decompression callback for brotli algorithm
extern "C" fn cert_decompress_brotli(
    _ssl: *mut Ssl,
    out: *mut *mut CryptoBuffer,
    uncompressed_len: usize,
    in_data: *const u8,
    in_len: usize,
) -> c_int {
    use std::io::Read;

    let compressed = unsafe { std::slice::from_raw_parts(in_data, in_len) };
    let mut decompressed = vec![0u8; uncompressed_len];

    match brotli::Decompressor::new(compressed, 4096).read_exact(&mut decompressed) {
        Ok(()) => {
            let buffer = unsafe {
                CRYPTO_BUFFER_new(
                    decompressed.as_ptr(),
                    decompressed.len(),
                    std::ptr::null_mut(),
                )
            };
            if buffer.is_null() {
                return 0;
            }
            unsafe {
                *out = buffer;
            }
            1
        }
        Err(_) => 0,
    }
}

fn map_result_ptr<'a, T>(bssl_result: *const T) -> Result<&'a T> {
    match unsafe { bssl_result.as_ref() } {
        Some(v) => Ok(v),
        None => Err(Error::TlsFail("pointer as reference error".to_string())),
    }
}

fn get_ssl_error() -> Result<String> {
    let mut err = [0u8; 1024];

    unsafe {
        let e = ERR_peek_error();
        ERR_error_string_n(e, err.as_mut_ptr() as *mut c_char, err.len());
    }

    let err = std::str::from_utf8(&err)
        .map_err(|e| Error::TlsFail(format!("ssl error message format incorrect: {:?}", e)))?;

    Ok(err.trim_end_matches('\0').to_string())
}
