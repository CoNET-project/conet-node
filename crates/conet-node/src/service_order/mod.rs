//! DePIN service orders paid in a third-party stable token: the node receives a user's offline
//! EIP-712 authorization, checks it, and (decided flow) submits it for the user. LOCAL PROTOTYPE:
//! no production signer entry exists (not approved); submission is tested only with test keys
//! on a local chain once fork 4's contract exists.
//!
//! Generic parts live here (they do not depend on the final order layout): the domain check,
//! the two signature paths (EOA ECDSA; ERC-1271 for Beamio smart wallets with a code-hash
//! allowlist, a gas cap and a timeout), random-nonce de-duplication, the deadline against chain
//! time, and the ordered precheck. Every draft field, view and error name is in [`draft`].
pub mod draft;

use crate::chain::{parse_rpc_data, ChainError, Rpc};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{Eip712Domain, SolCall};
use draft::{FreeClosedMode, ReceiptView, SettlementConfig, SettlementOrder, Source};
use std::collections::HashMap;
use std::time::Duration;

/// Why an authorization or an order is refused. Names follow the draft's contract errors where
/// one exists, so the node's answer and the contract's revert can be compared one to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refuse {
    /// The domain the client claims is not the one the node verifies against.
    Domain(&'static str),
    /// The token is not on the node's list of factory-deployed, DAO-registered tokens.
    TokenNotAllowed(Address),
    /// Signature malformed or not by `user` (contract: `BadSignature`).
    BadSignature(&'static str),
    /// The user is a contract that is not an accepted Beamio wallet (code hash not listed).
    WalletNotAccepted(B256),
    /// The ERC-1271 call did not answer in time or used its gas cap.
    WalletCallFailed(String),
    /// The order names another node or another node wallet (contract: `NodeIdMismatch`).
    NotForThisNode,
    /// This node lacks the service bit the order asks for (contract: `ServiceMissing`).
    ServiceMissing,
    /// Zero amount (contract: `ZeroAmount`) or an unknown pool.
    BadField(&'static str),
    /// Pool switched off (contract: `PoolDisabled` / `FreeExchangeOff`).
    PoolDisabled,
    FreeExchangeOff,
    /// A bound version differs from the active one (contract: `VersionMismatch`).
    VersionMismatch {
        item: &'static str,
        active: u64,
        signed: u64,
    },
    /// Past the deadline by chain time (contract: `OrderExpired`), or too close to it to land.
    OrderExpired,
    TooCloseToDeadline,
    /// Deadline further ahead than the node accepts (node policy, no contract counterpart).
    DeadlineTooFar,
    /// Same (user, nonce) already seen by this node or used on chain (contract: `NonceUsed`).
    NonceUsed,
    /// The pay exceeds the user's cap (contract: `ExceedsMaxPay`).
    ExceedsMaxPay {
        pay: U256,
        max: U256,
    },
    /// The user's balance in the chosen pool cannot cover the pay (no fallback to the other pool).
    BalanceShort {
        have: U256,
        need: U256,
    },
    /// RECEIPT order without a readable receipt, a receipt of another token, or not held by the
    /// signer now (transferred away).
    ReceiptNotHeld,
    /// Outside the receipt's validity period (chain time).
    ReceiptExpired,
    /// The receipt's remaining free amount cannot cover the pay.
    ReceiptQuotaShort {
        left: U256,
        need: U256,
    },
    /// The issuer's prepaid GB does not cover the order (contract: `InsufficientInventory`).
    InsufficientInventory {
        have: U256,
        need: U256,
    },
    /// The local simulation of `settle` reverted with this contract error.
    Simulated(String),
}

impl Refuse {
    /// The draft contract error this refusal corresponds to (None = node-only policy).
    pub fn contract_error(&self) -> Option<&'static str> {
        Some(match self {
            Refuse::BadSignature(_)
            | Refuse::WalletNotAccepted(_)
            | Refuse::WalletCallFailed(_) => "BadSignature",
            Refuse::NotForThisNode => "NodeIdMismatch",
            Refuse::ServiceMissing => "ServiceMissing",
            Refuse::BadField(_) => "ZeroAmount",
            Refuse::PoolDisabled => "PoolDisabled",
            Refuse::FreeExchangeOff => "FreeExchangeOff",
            Refuse::VersionMismatch { .. } => "VersionMismatch",
            Refuse::OrderExpired => "OrderExpired",
            Refuse::NonceUsed => "NonceUsed",
            Refuse::ExceedsMaxPay { .. } => "ExceedsMaxPay",
            Refuse::InsufficientInventory { .. } => "InsufficientInventory",
            _ => return None,
        })
    }
}

// ---- domain ----

/// Tokens this node settles for (factory-deployed and DAO-registered; filled from chain reads by
/// the caller, never from the client).
#[derive(Debug, Clone, Default)]
pub struct TokenAllowlist(pub Vec<Address>);

/// A domain the client says it signed under must equal the one the node computes: name,
/// version, chain id, verifying contract = an allowed token, no salt.
pub fn check_domain(
    claimed: &Eip712Domain,
    token: Address,
    allow: &TokenAllowlist,
) -> Result<(), Refuse> {
    if !allow.0.contains(&token) {
        return Err(Refuse::TokenNotAllowed(token));
    }
    let want = draft::domain(token);
    if claimed.name != want.name {
        return Err(Refuse::Domain("name"));
    }
    if claimed.version != want.version {
        return Err(Refuse::Domain("version"));
    }
    if claimed.chain_id != want.chain_id {
        return Err(Refuse::Domain("chainId"));
    }
    if claimed.verifying_contract != want.verifying_contract {
        return Err(Refuse::Domain("verifyingContract"));
    }
    if claimed.salt.is_some() {
        return Err(Refuse::Domain("salt"));
    }
    Ok(())
}

// ---- signatures ----

/// secp256k1 order / 2: a valid Ethereum signature has s at or below it.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// EOA path (DESIGN.md §6.3 step 2): 65 bytes r||s||v, v = 27 or 28, low s, recovers `user`.
/// EIP-7702 delegated EOAs take this path too.
pub fn verify_eoa(d: B256, sig: &[u8], user: Address) -> Result<(), Refuse> {
    if sig.len() != 65 {
        return Err(Refuse::BadSignature("length"));
    }
    if sig[64] != 27 && sig[64] != 28 {
        return Err(Refuse::BadSignature("v"));
    }
    if sig[32..64] > HALF_N[..] {
        return Err(Refuse::BadSignature("high s"));
    }
    let got = si_crypto::eth::recover_digest(&d.0, &format!("0x{}", hex::encode(sig)))
        .map_err(|_| Refuse::BadSignature("recover"))?;
    let got: Address = got.parse().map_err(|_| Refuse::BadSignature("recover"))?;
    if got != user {
        return Err(Refuse::BadSignature("not the user"));
    }
    Ok(())
}

/// Smart-wallet acceptance (ERC-1271, third-party tokens only; GB stays EOA-only).
///
/// The verdict is the wallet's own on-chain `isValidSignature(digest, sig)` answer (project
/// requirement): the node never re-implements a wallet's scheme (e.g. BeamioAccount's eth-sign
/// wrapping and ascending m-of-n managers) and treats `sig` as opaque; how it is built belongs to
/// the client and the Beamio signing protocol. The code-hash list only decides whether the node
/// is willing to make that call; it never replaces it.
#[derive(Debug, Clone)]
pub struct WalletPolicy {
    /// DRAFT: keccak256 of the runtime code of accepted Beamio factory wallets, until the
    /// authoritative source is decided (factory registry view or published code hash).
    pub accepted_code_hashes: Vec<B256>,
    /// Gas given to the `isValidSignature` eth_call.
    pub gas_cap: u64,
    pub timeout: Duration,
}

impl Default for WalletPolicy {
    fn default() -> Self {
        Self {
            accepted_code_hashes: vec![],
            gas_cap: 200_000,
            timeout: Duration::from_secs(5),
        }
    }
}

const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// ERC-1271 path (DESIGN.md §6.3 step 3): the user's code must be an accepted Beamio wallet
/// (checked before calling it), then `isValidSignature(d, sig)` with a gas cap and a timeout must
/// return 0x1626ba7e. Read at the latest block; the contract re-checks at settlement, so this is
/// a precheck (a wallet may change its managers before the order lands).
pub async fn verify_1271(
    rpc: &Rpc,
    d: B256,
    sig: &[u8],
    user: Address,
    p: &WalletPolicy,
) -> Result<(), Refuse> {
    let code = rpc
        .call("eth_getCode", serde_json::json!([user, "latest"]))
        .await
        .map_err(|e| Refuse::WalletCallFailed(e.0))?;
    let code = parse_rpc_data(&code, "eth_getCode")
        .map_err(|e| Refuse::WalletCallFailed(e.to_string()))?;
    if code.is_empty() {
        return Err(Refuse::BadSignature(
            "no code (undeployed wallets are refused)",
        ));
    }
    let h = keccak256(&code);
    if !p.accepted_code_hashes.contains(&h) {
        return Err(Refuse::WalletNotAccepted(h));
    }
    let data = draft::IERC1271::isValidSignatureCall {
        hash: d,
        signature: Bytes::copy_from_slice(sig),
    }
    .abi_encode();
    let call = rpc.call(
        "eth_call",
        serde_json::json!([{
            "to": user,
            "data": format!("0x{}", hex::encode(data)),
            "gas": format!("0x{:x}", p.gas_cap),
        }, "latest"]),
    );
    let v = tokio::time::timeout(p.timeout, call)
        .await
        .map_err(|_| Refuse::WalletCallFailed("timeout".into()))?
        .map_err(|e| Refuse::WalletCallFailed(e.0))?;
    let raw =
        parse_rpc_data(&v, "eth_call").map_err(|e| Refuse::WalletCallFailed(e.to_string()))?;
    if raw.len() >= 4 && raw[..4] == ERC1271_MAGIC {
        Ok(())
    } else {
        Err(Refuse::BadSignature("ERC-1271 rejected"))
    }
}

/// Both paths in the contract's order: ECDSA recovering `user` passes; otherwise a contract
/// user goes through ERC-1271; otherwise refused.
pub async fn verify_signature(
    rpc: &Rpc,
    d: B256,
    sig: &[u8],
    user: Address,
    p: &WalletPolicy,
) -> Result<(), Refuse> {
    match verify_eoa(d, sig, user) {
        Ok(()) => Ok(()),
        Err(eoa) => match verify_1271(rpc, d, sig, user, p).await {
            Ok(()) => Ok(()),
            // An EOA user: report the ECDSA reason, not "no code".
            Err(Refuse::BadSignature("no code (undeployed wallets are refused)")) => Err(eoa),
            Err(e) => Err(e),
        },
    }
}

// ---- nonce and deadline ----

/// Random 32-byte nonces seen by this node, per user. An entry is held while an order is in
/// flight and kept once it settled; a failed settlement releases it (the contract does not
/// consume a nonce on failure). Entries are dropped after their deadline (the contract refuses
/// them by then anyway).
#[derive(Debug, Default)]
pub struct NonceBook {
    seen: HashMap<(Address, B256), (u64, bool)>,
}

impl NonceBook {
    /// Hold (user, nonce) until `deadline`; refuses a duplicate.
    pub fn hold(&mut self, user: Address, nonce: B256, deadline: u64) -> Result<(), Refuse> {
        if self.seen.contains_key(&(user, nonce)) {
            return Err(Refuse::NonceUsed);
        }
        self.seen.insert((user, nonce), (deadline, false));
        Ok(())
    }
    /// The order settled on chain: the nonce stays used.
    pub fn settled(&mut self, user: Address, nonce: B256) {
        if let Some(e) = self.seen.get_mut(&(user, nonce)) {
            e.1 = true;
        }
    }
    /// The order failed: the user may submit the same signed order again before its deadline.
    pub fn release(&mut self, user: Address, nonce: B256) {
        if let Some((_, false)) = self.seen.get(&(user, nonce)) {
            self.seen.remove(&(user, nonce));
        }
    }
    /// Forget entries whose deadline passed at chain time `now`.
    pub fn prune(&mut self, now: u64) {
        self.seen.retain(|_, (d, _)| *d >= now);
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Node policy for deadlines, compared with CHAIN time (the confirmed block's timestamp).
#[derive(Debug, Clone, Copy)]
pub struct DeadlinePolicy {
    /// Refuse an order that would expire within this many seconds (it may not land in time).
    pub min_left: u64,
    /// Refuse an order valid for longer than this (no long-lived authorizations held).
    pub max_ahead: u64,
}

impl Default for DeadlinePolicy {
    fn default() -> Self {
        Self {
            min_left: 60,
            max_ahead: 3_600,
        }
    }
}

/// The contract accepts `block.timestamp <= deadline`.
pub fn check_deadline(deadline: u64, chain_now: u64, p: DeadlinePolicy) -> Result<(), Refuse> {
    if chain_now > deadline {
        return Err(Refuse::OrderExpired);
    }
    if deadline - chain_now < p.min_left {
        return Err(Refuse::TooCloseToDeadline);
    }
    if deadline - chain_now > p.max_ahead {
        return Err(Refuse::DeadlineTooFar);
    }
    Ok(())
}

// ---- precheck ----

/// This node, as the registry knows it.
#[derive(Debug, Clone)]
pub struct Me {
    pub node_id: u64,
    pub node_wallet: Address,
    /// The node's service bits, as `bytes32` (the order's `serviceBit` must be among them).
    pub services: B256,
}

/// Token state read from one block (draft views).
#[derive(Debug, Clone)]
pub struct TokenView {
    pub now: u64,
    pub config: SettlementConfig,
    pub paid_balance: U256,
    pub free_balance: U256,
    pub inventory_gb: U256,
    /// (pBase, markup bps) when the node can read them (no view in the draft yet).
    pub price: Option<(U256, u32)>,
    /// The creator's choice for ordinary free balances while the free pool is closed.
    pub free_closed_mode: FreeClosedMode,
}

/// Field, node, source, version, deadline, amount, inventory and nonce checks, in the order of
/// the draft's settlement (DESIGN.md §7.2 / §7.3; the signature is checked separately, async).
/// The first failure is returned. `receipt` is the receipt state for a RECEIPT order (None
/// otherwise). `nonces` is only touched when everything else passed.
pub fn precheck(
    o: &SettlementOrder,
    me: &Me,
    t: &TokenView,
    receipt: Option<&ReceiptView>,
    token: Address,
    deadline: DeadlinePolicy,
    nonces: &mut NonceBook,
) -> Result<(), Refuse> {
    // Node.
    if o.nodeId != me.node_id || o.nodeWallet != me.node_wallet {
        return Err(Refuse::NotForThisNode);
    }
    if o.serviceBit.is_zero() || (o.serviceBit & me.services) != o.serviceBit {
        return Err(Refuse::ServiceMissing);
    }
    // Fields.
    let Some(src) = draft::source(o) else {
        return Err(Refuse::BadField("pool"));
    };
    if o.minNodeGb.is_zero() || o.maxUserPay.is_zero() {
        return Err(Refuse::BadField("zero amount"));
    }
    // Source state; never falls back to another source.
    match src {
        Source::Paid => {}
        Source::Free => {
            if !t.config.freePoolOn && t.free_closed_mode == FreeClosedMode::Freeze {
                return Err(Refuse::PoolDisabled);
            }
            if !t.config.freeExchangeOn {
                return Err(Refuse::FreeExchangeOff);
            }
        }
        Source::Receipt => {
            let r = receipt.ok_or(Refuse::ReceiptNotHeld)?;
            if r.token != token || r.holder_balance != U256::from(1) {
                return Err(Refuse::ReceiptNotHeld);
            }
            if t.now < r.valid_from || t.now > r.valid_until {
                return Err(Refuse::ReceiptExpired);
            }
        }
    }
    // Versions bound by this source.
    for (item, signed, active) in draft::bound_versions(o, &t.config) {
        if signed != active {
            return Err(Refuse::VersionMismatch {
                item,
                active,
                signed,
            });
        }
    }
    check_deadline(o.deadline, t.now, deadline)?;
    // Amount: exact when the price inputs are known; otherwise the simulation decides.
    if let Some((p_base, m)) = t.price {
        let pay = draft::user_pay(o.minNodeGb, p_base, m);
        if pay > o.maxUserPay {
            return Err(Refuse::ExceedsMaxPay {
                pay,
                max: o.maxUserPay,
            });
        }
        match src {
            Source::Paid | Source::Free => {
                let have = if src == Source::Free {
                    t.free_balance
                } else {
                    t.paid_balance
                };
                if have < pay {
                    return Err(Refuse::BalanceShort { have, need: pay });
                }
            }
            Source::Receipt => {
                let r = receipt.expect("checked above");
                if let Some(q) = r.quota {
                    let left = q.saturating_sub(r.used);
                    if left < pay {
                        return Err(Refuse::ReceiptQuotaShort { left, need: pay });
                    }
                }
            }
        }
    }
    if t.inventory_gb < o.minNodeGb {
        return Err(Refuse::InsufficientInventory {
            have: t.inventory_gb,
            need: o.minNodeGb,
        });
    }
    nonces.hold(o.user, o.nonce, o.deadline)
}

/// `settle(order, auth)` calldata (draft selector and layout).
pub fn settle_calldata(o: &SettlementOrder, auth: &[u8]) -> Vec<u8> {
    draft::IThirdPartyStableLedger::settleCall {
        order: o.clone(),
        auth: Bytes::copy_from_slice(auth),
    }
    .abi_encode()
}

/// Last precheck step: simulate `settle` from this node's wallet at the latest block. A revert
/// comes back as the draft contract error name (covers what the node cannot read itself, such
/// as a nonce used on chain or the exact pay).
pub async fn simulate_settle(
    rpc: &Rpc,
    token: Address,
    from: Address,
    o: &SettlementOrder,
    auth: &[u8],
) -> Result<(U256, U256), Refuse> {
    let data = settle_calldata(o, auth);
    let r = rpc
        .call(
            "eth_call",
            serde_json::json!([{ "from": from, "to": token, "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )
        .await;
    match r {
        Ok(v) => {
            let raw =
                parse_rpc_data(&v, "eth_call").map_err(|e| Refuse::Simulated(e.to_string()))?;
            let out = draft::IThirdPartyStableLedger::settleCall::abi_decode_returns(&raw)
                .map_err(|e| Refuse::Simulated(e.to_string()))?;
            Ok((out.userPaid, out.gbSent))
        }
        Err(ChainError(e)) => Err(Refuse::Simulated(revert_name(&e).unwrap_or(e))),
    }
}

/// Pull revert data ("0x…") out of a JSON-RPC error text and name it with the draft errors.
fn revert_name(err: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(err).ok()?;
    let data = v.get("data")?.as_str()?;
    let raw = hex::decode(data.trim_start_matches("0x")).ok()?;
    draft::error_name(&raw).map(str::to_string)
}
