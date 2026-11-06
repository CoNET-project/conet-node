//! Blocking client used by the network process. Implements the core traits, so `si-core`
//! runs unchanged whether keys are in-process (tests) or behind the signer.
use crate::proto::{self, Request, Response};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use si_core::{NodeNotices, RouteDecryptor, WalletSigner};
use si_crypto::{eth, Error, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub struct SignerClient {
    path: PathBuf,
    address: String,
    key_id: String,
    old_key_ids: Vec<String>,
    timeout: Duration,
}

impl SignerClient {
    pub fn connect(path: impl Into<PathBuf>) -> Result<Self> {
        let mut c = Self {
            path: path.into(),
            address: String::new(),
            key_id: String::new(),
            old_key_ids: vec![],
            timeout: Duration::from_secs(5),
        };
        c.address = c.call(&Request::Address)?;
        c.key_id = c.call(&Request::RouteKeyId)?;
        c.old_key_ids = c
            .call(&Request::OldRouteKeyIds)?
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        Ok(c)
    }

    pub fn route_key_id(&self) -> &str {
        &self.key_id
    }

    pub fn old_route_key_ids(&self) -> &[String] {
        &self.old_key_ids
    }

    pub fn call(&self, req: &Request) -> Result<String> {
        let io = |e: std::io::Error| Error::Eth(format!("signer io: {e}"));
        let mut s = UnixStream::connect(&self.path).map_err(io)?;
        s.set_read_timeout(Some(self.timeout)).map_err(io)?;
        s.set_write_timeout(Some(self.timeout)).map_err(io)?;
        s.write_all(&proto::encode(req)).map_err(io)?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).map_err(io)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > proto::MAX_FRAME {
            return Err(Error::Eth("signer frame too large".into()));
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).map_err(io)?;
        match serde_json::from_slice::<Response>(&buf).map_err(|e| Error::Eth(e.to_string()))? {
            Response::Ok { value } => Ok(value),
            Response::Refused { reason } => Err(Error::Eth(format!("signer refused: {reason}"))),
        }
    }
}

impl RouteDecryptor for SignerClient {
    fn decrypt(&self, armor: &str) -> Result<Vec<u8>> {
        // Only the PKESK goes to the signer; decompression and parsing stay here.
        let pkesk = si_crypto::opgp::pkesk_packet(armor)?;
        let v = zeroize::Zeroizing::new(self.call(&Request::RouteSessionKey {
            pkesk: B64.encode(pkesk),
        })?);
        let (alg, key) = v
            .split_once(':')
            .ok_or_else(|| Error::Pgp("signer reply".into()))?;
        let alg: u8 = alg.parse().map_err(|_| Error::Pgp("signer reply".into()))?;
        let key = zeroize::Zeroizing::new(B64.decode(key).map_err(|e| Error::Pgp(e.to_string()))?);
        si_crypto::opgp::decrypt_with_session_key(armor, alg, &key)
    }
}

impl WalletSigner for SignerClient {
    fn address(&self) -> String {
        self.address.clone()
    }
    /// Only hop payloads are accepted: parse ours back into fields for the signer.
    fn sign_message(&self, message: &str) -> Result<String> {
        let p: Vec<&str> = message.split('|').collect();
        if p.len() != 6
            || p[0] != si_proto::HOP_SIG_DOMAIN
            || !eth::to_checksum(p[1]).eq_ignore_ascii_case(&self.address)
        {
            return Err(Error::Eth("signer only signs hop payloads".into()));
        }
        let t = p[2].parse().map_err(|_| Error::Eth("hop t".into()))?;
        let n = p[3].parse().map_err(|_| Error::Eth("hop n".into()))?;
        self.call(&Request::SignHop {
            t,
            n,
            h: p[4].to_string(),
            k: p[5].to_string(),
        })
    }
}

impl NodeNotices for SignerClient {
    fn sign_voice_call_push(
        &self,
        call_id: &str,
        session_id: &str,
        callee_eoa: &str,
        expires_at: i64,
        timestamp: i64,
    ) -> Result<String> {
        self.call(&Request::SignVoiceCallPush {
            call_id: call_id.into(),
            session_id: session_id.into(),
            callee_eoa: callee_eoa.into(),
            expires_at,
            timestamp,
        })
    }
    fn sign_epoch(&self, epoch: u64) -> Result<String> {
        self.call(&Request::SignEpoch { epoch })
    }
    fn sign_offline_chat(&self, pgp_key_id: &str, eoa: &str, timestamp: u64) -> Result<String> {
        self.call(&Request::SignOfflineChat {
            pgp_key_id: pgp_key_id.into(),
            eoa: eoa.into(),
            timestamp,
        })
    }
    fn sign_native_wakeable(&self, eoa: &str, timestamp: u64) -> Result<String> {
        self.call(&Request::SignNativeWakeable {
            eoa: eoa.into(),
            timestamp,
        })
    }
}
