//! Owner signature: for the owner-bound commands a message whose `walletAddress` is not the wallet that signed is accepted only with the owner's signature over the
//! statement for that exact message. Test wallets come from the public conformance vectors.
use serde_json::{json, Value};
use si_core::{check_sign, check_sign_with_owner};
use si_crypto::eth::{self, EthKey};
use si_proto::owner_statement;

fn wallet(name: &str) -> EthKey {
    let p = format!(
        "{}/../../conformance/vectors/golden.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let g: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    EthKey::from_hex(g["wallets"][name]["privateKey"].as_str().unwrap()).unwrap()
}

fn msg(command: &str, wallet_addr: &str, billing: Option<&str>) -> String {
    let mut m =
        json!({ "command": command, "walletAddress": wallet_addr, "timestamp": 1_794_005_886u64 });
    if let Some(b) = billing {
        m["billingWallet"] = json!(b);
    }
    m.to_string()
}

fn owner_proof(owner: &EthKey, message: &str) -> String {
    owner
        .sign_message(&owner_statement(&eth::keccak_hex(message)))
        .unwrap()
}

#[test]
fn a_wallet_acting_for_itself_needs_no_owner_signature() {
    let a = wallet("client");
    for cmd in ["mailbox_listen", "gossip_delivery_ack"] {
        let m = msg(cmd, &a.address(), None);
        assert!(
            check_sign(&m, &a.sign_message(&m).unwrap()).is_some(),
            "{cmd}"
        );
        let m = msg(cmd, &a.address(), Some(&a.address()));
        assert!(
            check_sign(&m, &a.sign_message(&m).unwrap()).is_some(),
            "{cmd} with the same billing wallet"
        );
    }
}

#[test]
fn owner_bound_commands_need_the_owner_signature_when_another_wallet_signs() {
    let (owner, payer) = (wallet("client"), wallet("other"));
    for cmd in si_proto::OWNER_BOUND_COMMANDS {
        let m = msg(cmd, &owner.address(), Some(&payer.address()));
        let sig = payer.sign_message(&m).unwrap();
        assert!(check_sign(&m, &sig).is_none(), "{cmd}: no owner signature");
        assert!(
            check_sign_with_owner(&m, &sig, None).is_none(),
            "{cmd}: explicit none"
        );
        assert!(
            check_sign_with_owner(&m, &sig, Some("0x")).is_none(),
            "{cmd}: malformed"
        );
    }
}

#[test]
fn a_valid_owner_signature_keeps_delegated_payment_working() {
    let (owner, payer) = (wallet("client"), wallet("other"));
    for cmd in si_proto::OWNER_BOUND_COMMANDS {
        let m = msg(cmd, &owner.address(), Some(&payer.address()));
        let out = check_sign_with_owner(
            &m,
            &payer.sign_message(&m).unwrap(),
            Some(&owner_proof(&owner, &m)),
        )
        .unwrap_or_else(|| panic!("{cmd}"));
        assert_eq!(out["walletAddress"], owner.address().to_lowercase());
        assert_eq!(out["billingWallet"], payer.address().to_lowercase());
    }
}

#[test]
fn an_owner_signature_that_does_not_belong_to_this_message_is_refused() {
    let (owner, payer, third) = (wallet("client"), wallet("other"), wallet("nodeA"));
    let m = msg("mailbox_listen", &owner.address(), Some(&payer.address()));
    let sig = payer.sign_message(&m).unwrap();
    // signed by a wallet that is not the owner
    assert!(check_sign_with_owner(&m, &sig, Some(&owner_proof(&third, &m))).is_none());
    // the owner's proof for a different message (a different command, a different timestamp, a different payer)
    for other in [
        msg("gossip_delivery_ack", &owner.address(), Some(&payer.address())),
        msg("mailbox_listen", &owner.address(), Some(&third.address())),
        json!({ "command": "mailbox_listen", "walletAddress": owner.address(), "billingWallet": payer.address(), "timestamp": 1_794_005_887u64 }).to_string(),
    ] {
        assert!(check_sign_with_owner(&m, &sig, Some(&owner_proof(&owner, &other))).is_none());
    }
    // the proof is a signature of the statement, not of the bare message or of its hash
    assert!(check_sign_with_owner(&m, &sig, Some(&owner.sign_message(&m).unwrap())).is_none());
    assert!(check_sign_with_owner(
        &m,
        &sig,
        Some(&owner.sign_message(&eth::keccak_hex(&m)).unwrap())
    )
    .is_none());
    // the outer signature must still be the payer's
    let other_outer = third.sign_message(&m).unwrap();
    assert!(check_sign_with_owner(&m, &other_outer, Some(&owner_proof(&owner, &m))).is_none());
}

#[test]
fn commands_that_are_not_owner_bound_keep_the_payer_rule() {
    // udp_listen carries a session id; the conformance vector "post-cmd-billing" expects this shape to be accepted
    let (owner, payer) = (wallet("client"), wallet("other"));
    let m = msg("udp_listen", &owner.address(), Some(&payer.address()));
    assert!(check_sign(&m, &payer.sign_message(&m).unwrap()).is_some());
    // and a wallet that signs for another wallet without any billing field is still refused for every command
    let m = msg("udp_listen", &owner.address(), None);
    assert!(check_sign(&m, &payer.sign_message(&m).unwrap()).is_none());
}
