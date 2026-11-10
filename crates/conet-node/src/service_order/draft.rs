//! DRAFT FIELDS: to be compared with fork 4's ABI once it is final.
//!
//! Source: GB fork 5 interface draft `IThirdPartyStableLedger.sol` and `DESIGN.md` v0.2
//! (GB worktree commit 8e43083c, `scripts/gb-newgen/third-party-stable/`). Everything that
//! depends on the order layout, the domain, the view names or the error names lives in this file
//! only, so the final ABI changes one place. Not deployed; no address is known.
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, Eip712Domain, SolStruct};

sol! {
    /// The order a user signs (DESIGN.md §6.2). `pool`: 0 = PAID, 1 = FREE (the Solidity enum
    /// is encoded as uint8 in EIP-712).
    #[derive(Debug, PartialEq, Eq)]
    struct SettlementOrder {
        uint8 pool;
        address user;
        uint64 nodeId;
        address nodeWallet;
        uint256 minNodeGb;
        uint256 maxUserPay;
        uint64 gbBaseVersion;
        uint64 markupVersion;
        uint64 freeExchangeVersion;
        uint64 freePoolVersion;
        bytes32 serviceBit;
        uint64 deadline;
        bytes32 nonce;
    }

    /// `settlementConfig()` (DESIGN.md §6.4, §15.4).
    #[derive(Debug, PartialEq, Eq)]
    struct SettlementConfig {
        bool freePoolOn;
        uint64 freePoolVersion;
        bool freeExchangeOn;
        uint64 freeExchangeVersion;
        uint64 markupVersion;
        uint64 gbBaseVersion;
    }

    /// The calls and errors the node uses (subset of the draft interface).
    interface IThirdPartyStableLedger {
        error NotCreator();
        error ZeroAddress();
        error ZeroAmount();
        error PoolDisabled(uint8 pool);
        error FreeExchangeOff();
        error FreeTransferOff();
        error VersionMismatch(uint64 active, uint64 signed);
        error OrderExpired(uint64 deadline);
        error NonceUsed(address user, bytes32 nonce);
        error BadSignature(address user);
        error NodeNotActive(address nodeWallet);
        error NodeIdMismatch(uint64 nodeId, uint64 walletNodeId);
        error ServiceMissing(bytes32 serviceBit);
        error NodeLeaked(address nodeWallet);
        error ExceedsMaxPay(uint256 pay, uint256 maxPay);
        error InsufficientInventory(uint256 have, uint256 need);
        error AmountChanged(uint256 signed, uint256 current);

        function settlementConfig() external view returns (SettlementConfig memory);
        function paidBalanceOf(address account) external view returns (uint256);
        function freeBalanceOf(address account) external view returns (uint256);
        function inventoryGb() external view returns (uint256);
        function settle(SettlementOrder calldata order, bytes calldata auth) external returns (uint256 userPaid, uint256 gbSent);
    }

    /// ERC-1271 (smart wallets, DESIGN.md §6.3).
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4 magicValue);
    }
}

pub const POOL_PAID: u8 = 0;
pub const POOL_FREE: u8 = 1;
/// PLACEHOLDER until fork 5 v0.4: the subscription-receipt (ERC1155) source. The 8e43083c draft
/// has no receipt field in the signed order; the prototype carries `receiptId` beside it.
pub const POOL_RECEIPT: u8 = 2;

/// Where an order's payment comes from (decided 2026-11-10). The three are independent: a FREE
/// pool close or freeze never touches RECEIPT orders, and RECEIPT orders bind no FREE versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Ordinary paid balance.
    Paid,
    /// Ordinary free balance.
    Free,
    /// A subscription receipt (ERC1155, one per subscription).
    Receipt,
}

pub fn source(o: &SettlementOrder) -> Option<Source> {
    match o.pool {
        POOL_PAID => Some(Source::Paid),
        POOL_FREE => Some(Source::Free),
        POOL_RECEIPT => Some(Source::Receipt),
        _ => None,
    }
}

/// What the creator chose for existing ordinary free balances while the free pool is closed
/// (decided 2026-11-10; view name and encoding pending fork 5 v0.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeClosedMode {
    /// A: frozen; FREE orders are not submitted while the pool is closed.
    Freeze,
    /// B: still usable; FREE orders go on (versions and the exchange switch still apply).
    KeepUsable,
}

/// A subscription receipt as the node reads it (PLACEHOLDER fields until fork 5 v0.4). The quota
/// is "the maximum free stable-token amount" (project wording): counted in the third-party
/// token, per receipt, never reset, kept across transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptView {
    pub receipt_id: U256,
    /// The token the receipt belongs to (must be the order's token).
    pub token: Address,
    /// ERC1155 `balanceOf(order.user, receiptId)`: 1 = the signer holds it now.
    pub holder_balance: U256,
    pub valid_from: u64,
    pub valid_until: u64,
    /// None = unlimited.
    pub quota: Option<U256>,
    pub used: U256,
}

/// DESIGN.md §6.1.
pub const DOMAIN_NAME: &str = "ThirdPartyStableSettlement";
pub const DOMAIN_VERSION: &str = "1";
pub const CHAIN_ID: u64 = 224_422;

/// The type string the draft gives for the implementation (checked against `sol!` in tests).
pub const TYPE_STRING: &str = "SettlementOrder(uint8 pool,address user,uint64 nodeId,address nodeWallet,uint256 minNodeGb,uint256 maxUserPay,uint64 gbBaseVersion,uint64 markupVersion,uint64 freeExchangeVersion,uint64 freePoolVersion,bytes32 serviceBit,uint64 deadline,bytes32 nonce)";

/// The domain an order for `token` is signed under: the token is the verifying contract.
pub fn domain(token: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some(DOMAIN_NAME.into()),
        Some(DOMAIN_VERSION.into()),
        Some(U256::from(CHAIN_ID)),
        Some(token),
        None,
    )
}

/// The EIP-712 digest `d` both signature paths check (DESIGN.md §6.3 step 1).
pub fn digest(order: &SettlementOrder, token: Address) -> B256 {
    order.eip712_signing_hash(&domain(token))
}

/// The versions an order binds, by source (DESIGN.md §6.4 table and the 2026-11-10 decisions):
/// (name, signed, active). PAID: GB base price and markup. FREE: also both free-pool switches.
/// RECEIPT: none of the ordinary-pool versions (independent of the free pool); what a receipt
/// order binds besides `receiptId` is pending fork 5 v0.4. Unrelated items (airdrop amount,
/// free-transfer switch) are never compared.
pub fn bound_versions(o: &SettlementOrder, c: &SettlementConfig) -> Vec<(&'static str, u64, u64)> {
    match source(o) {
        Some(Source::Paid) => vec![
            ("gbBaseVersion", o.gbBaseVersion, c.gbBaseVersion),
            ("markupVersion", o.markupVersion, c.markupVersion),
        ],
        Some(Source::Free) => vec![
            ("gbBaseVersion", o.gbBaseVersion, c.gbBaseVersion),
            ("markupVersion", o.markupVersion, c.markupVersion),
            (
                "freeExchangeVersion",
                o.freeExchangeVersion,
                c.freeExchangeVersion,
            ),
            ("freePoolVersion", o.freePoolVersion, c.freePoolVersion),
        ],
        Some(Source::Receipt) | None => vec![],
    }
}

/// User pay for `g` GB base units (DESIGN.md §7.1, draft): ceilDiv(G x pBase x (10000 + m),
/// 1e9 x 10000), rounding for the issuer. `p_base` = U base units per whole GB (1e9 GB units);
/// `markup_bps` = m. The token draft has no view for m and pBase is read from the DAO: both are
/// inputs here until the final ABI says where the node reads them.
pub fn user_pay(g: U256, p_base: U256, markup_bps: u32) -> U256 {
    let num = g * p_base * U256::from(10_000u64 + markup_bps as u64);
    let den = U256::from(1_000_000_000u64) * U256::from(10_000u64);
    num.div_ceil(den)
}

/// Contract error name of revert data (draft error set), for logs and the precheck result.
pub fn error_name(data: &[u8]) -> Option<&'static str> {
    use alloy_sol_types::SolError;
    use IThirdPartyStableLedger as I;
    macro_rules! names {
        ($($t:ident),*) => { [$((I::$t::SELECTOR, stringify!($t))),*] };
    }
    let table = names!(
        NotCreator,
        ZeroAddress,
        ZeroAmount,
        PoolDisabled,
        FreeExchangeOff,
        FreeTransferOff,
        VersionMismatch,
        OrderExpired,
        NonceUsed,
        BadSignature,
        NodeNotActive,
        NodeIdMismatch,
        ServiceMissing,
        NodeLeaked,
        ExceedsMaxPay,
        InsufficientInventory,
        AmountChanged
    );
    let sel: [u8; 4] = data.get(..4)?.try_into().ok()?;
    table.iter().find(|(s, _)| *s == sel).map(|(_, n)| *n)
}
