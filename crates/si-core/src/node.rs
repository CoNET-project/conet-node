//! Sans-IO node: one `/post` request in, one step out. The host owns sockets, clock,
//! route lookups and storage; this only decides. Mirrors CoNET-SI rev 74c6cfd:
//! `postOpenpgpRouteSocket` → `forwardEncryptedSocket` → `signAndAppendHop`.
use crate::{classify_post, sign_hop, verify_hop, Decision, LocalRoute, WalletSigner, WriteKeys};
use serde_json::Value;
use si_crypto::opgp;
use si_proto as proto;

#[derive(Debug, PartialEq)]
pub enum Step {
    /// Look up `key_id`. If the route is this node, store `armor` for that key (mailbox);
    /// if it is another node, call [`Node::forward_header`] and forward `armor` there.
    Route {
        key_id: String,
        armor: String,
        no_push: bool,
        hops: Vec<proto::HopSig>,
    },
    /// Hand to the command dispatcher. `hops` are the parsed incoming rows (for GB metering).
    Command {
        command: Value,
        signed: bool,
        hops: Vec<proto::HopSig>,
    },
    /// SI `handleVoiceChunk`: the host checks `mac` with the target session's write key.
    VoiceChunk {
        locator: String,
        mac: [u8; 16],
        blob: Vec<u8>,
    },
    /// End the socket. `attack` = SI `terminateByEnd` (plain end), else 404 page (`distorySocket`).
    Close { reason: &'static str, attack: bool },
}

pub struct Node<'a> {
    pub route: LocalRoute<'a>,
    pub wallet: &'a dyn WalletSigner,
    pub write_keys: WriteKeys,
}

impl Node<'_> {
    pub fn on_post(&self, header_lines: &[&str], body_json: &str) -> Step {
        let Ok(body) = serde_json::from_str::<Value>(body_json) else {
            return Step::Close {
                reason: "body_json",
                attack: false,
            };
        };
        let Some(armor) = body.get("data").and_then(Value::as_str) else {
            return Step::Close {
                reason: "body_data",
                attack: false,
            };
        };
        // SI incomingHopSigsOrAttack: invalid header or more than 3 rows ends the socket.
        let hops = match proto::parse_hop_header(header_lines) {
            proto::HopHeader::Absent => vec![],
            proto::HopHeader::Rows(r) => r,
            proto::HopHeader::TooMany(_) => {
                return Step::Close {
                    reason: "hop_count",
                    attack: true,
                }
            }
            proto::HopHeader::Invalid => {
                return Step::Close {
                    reason: "hop_header",
                    attack: true,
                }
            }
        };
        if hops.iter().any(|h| !si_crypto::eth::is_address(&h.w)) {
            return Step::Close {
                reason: "hop_header",
                attack: true,
            };
        }
        match classify_post(armor, &self.route, &self.write_keys) {
            Decision::Forward { key_id } => Step::Route {
                key_id,
                armor: armor.to_string(),
                no_push: false,
                hops,
            },
            Decision::OnionForward { key_id, inner } => {
                if hops.len() >= proto::MAX_SI_HOP_SIGS {
                    return Step::Close {
                        reason: "hop_limit",
                        attack: true,
                    };
                }
                Step::Route {
                    key_id,
                    armor: inner,
                    no_push: false,
                    hops,
                }
            }
            Decision::MailboxWork {
                key_id,
                no_push,
                inner,
            } => Step::Route {
                key_id,
                armor: inner,
                no_push,
                hops,
            },
            Decision::AttackSameNode => Step::Close {
                reason: "same_node",
                attack: true,
            },
            Decision::VoiceChunk {
                locator, mac, blob, ..
            } => Step::VoiceChunk { locator, mac, blob },
            Decision::VoiceCommand { command } => self.command(command, false, hops),
            Decision::SignedCommand { command } => self.command(command, true, hops),
            Decision::Reject { reason } => Step::Close {
                reason,
                attack: false,
            },
        }
    }

    fn command(&self, command: Value, signed: bool, hops: Vec<proto::HopSig>) -> Step {
        let name = command.get("command").and_then(Value::as_str).unwrap_or("");
        if !proto::KNOWN_COMMANDS.contains(&name) {
            return Step::Close {
                reason: "unknown_command",
                attack: false,
            };
        }
        Step::Command {
            command,
            signed,
            hops,
        }
    }

    /// SI `signAndAppendHop`: refuse at 3 rows or when this wallet already signed; otherwise
    /// append our row and return the full header line for the next hop. `now` = unix seconds.
    pub fn forward_header(
        &self,
        incoming: &[proto::HopSig],
        next_key_id: &str,
        armor: &str,
        now: i64,
    ) -> Result<String, &'static str> {
        let me = self.wallet.address();
        if incoming.len() >= proto::MAX_SI_HOP_SIGS
            || incoming.iter().any(|h| h.w.eq_ignore_ascii_case(&me))
        {
            return Err("hop_limit");
        }
        let mut hops = incoming.to_vec();
        hops.push(sign_hop(self.wallet, armor, next_key_id, now).map_err(|_| "hop_sign")?);
        Ok(format!(
            "{}: {}",
            proto::SI_HOP_SIG_HEADER,
            proto::serialize_hop_header_value(&hops)
        ))
    }

    /// Prior-hop bytes to credit to the user (SI `creditUserGbFromHopSigs`).
    pub fn verified_hop_bytes(hops: &[proto::HopSig], now: i64) -> u64 {
        hops.iter()
            .filter(|h| verify_hop(h, now))
            .map(|h| h.n)
            .sum()
    }
}

/// Convenience for hosts: build the local route from armored key material (tests only;
/// the product loads the route key inside the signer process).
pub fn load_route(armor: &str, pass: &str) -> si_crypto::Result<(opgp::SecretCert, String)> {
    let key = opgp::SecretCert::from_armor(armor, pass)?.unlock()?;
    let id = key
        .public()
        .enc_key_id()
        .ok_or_else(|| si_crypto::Error::Pgp("no subkey".into()))?;
    Ok((key, id))
}
