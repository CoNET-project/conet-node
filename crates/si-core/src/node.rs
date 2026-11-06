//! Minimal sans-IO node: one `/post` request in, a list of actions out.
//! The host owns sockets, clock and signer; this only decides.
use crate::{classify_post, sign_hop, verify_hop, Decision, LocalRoute, WriteKeys};
use serde::Serialize;
use si_crypto::{eth, opgp};
use si_proto as proto;

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Forward `armor` to the node owning `key_id`, with this hop header line.
    Forward {
        #[serde(rename = "keyId")]
        key_id: String,
        armor_len: usize,
        hop_header: String,
        hops: usize,
    },
    /// Store / deliver to the local mailbox.
    DeliverLocal {
        #[serde(rename = "keyId")]
        key_id: String,
        no_push: bool,
    },
    /// Hand the command to the command dispatcher.
    Command {
        command: String,
    },
    VoiceChunk {
        locator: String,
    },
    /// End the socket (SI `terminateByEnd` / `distorySocket`).
    Close {
        reason: String,
    },
}

pub struct Node<'a> {
    pub route: LocalRoute<'a>,
    pub wallet: &'a eth::EthKey,
    pub write_keys: WriteKeys,
}

impl Node<'_> {
    /// `now` is unix seconds from the host clock.
    pub fn on_post(&self, header_lines: &[&str], body_json: &str, now: i64) -> Vec<Action> {
        let Ok(body) = serde_json::from_str::<serde_json::Value>(body_json) else {
            return vec![Action::Close {
                reason: "body_json".into(),
            }];
        };
        let Some(armor) = body.get("data").and_then(|v| v.as_str()) else {
            return vec![Action::Close {
                reason: "body_data".into(),
            }];
        };
        let hops = match proto::parse_hop_header(header_lines) {
            proto::HopHeader::Absent => vec![],
            proto::HopHeader::Rows(r) => r,
            proto::HopHeader::TooMany(_) | proto::HopHeader::Invalid => {
                return vec![Action::Close {
                    reason: "hop_sigs".into(),
                }]
            }
        };
        let valid: Vec<_> = hops.into_iter().filter(|h| verify_hop(h, now)).collect();
        match classify_post(armor, &self.route, &self.write_keys) {
            Decision::Forward { key_id } => self.forward(valid, &key_id, armor, now),
            Decision::OnionForward { key_id, inner } => {
                if valid.len() >= proto::MAX_SI_HOP_SIGS {
                    return vec![Action::Close {
                        reason: "hop_limit".into(),
                    }];
                }
                self.forward(valid, &key_id, &inner, now)
            }
            Decision::MailboxWork {
                key_id, no_push, ..
            } => vec![Action::DeliverLocal { key_id, no_push }],
            Decision::AttackSameNode => vec![Action::Close {
                reason: "same_node".into(),
            }],
            Decision::VoiceChunk {
                locator,
                mac_ok: true,
                ..
            } => vec![Action::VoiceChunk { locator }],
            Decision::VoiceChunk { .. } => vec![Action::Close {
                reason: "voice_mac".into(),
            }],
            Decision::VoiceCommand { command } | Decision::SignedCommand { command } => {
                let name = command
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !proto::KNOWN_COMMANDS.contains(&name.as_str()) {
                    return vec![Action::Close {
                        reason: "unknown_command".into(),
                    }];
                }
                vec![Action::Command { command: name }]
            }
            Decision::Reject { reason } => vec![Action::Close {
                reason: reason.into(),
            }],
        }
    }

    fn forward(
        &self,
        mut hops: Vec<proto::HopSig>,
        key_id: &str,
        armor: &str,
        now: i64,
    ) -> Vec<Action> {
        let me = self.wallet.address();
        if hops.len() >= proto::MAX_SI_HOP_SIGS
            || hops.iter().any(|h| h.w.eq_ignore_ascii_case(&me))
        {
            return vec![Action::Close {
                reason: "hop_limit".into(),
            }];
        }
        match sign_hop(self.wallet, armor, key_id, now) {
            Ok(h) => hops.push(h),
            Err(_) => {
                return vec![Action::Close {
                    reason: "hop_sign".into(),
                }]
            }
        }
        vec![Action::Forward {
            key_id: key_id.into(),
            armor_len: armor.len(),
            hop_header: format!(
                "{}: {}",
                proto::SI_HOP_SIG_HEADER,
                proto::serialize_hop_header_value(&hops)
            ),
            hops: hops.len(),
        }]
    }
}

/// Convenience for hosts: build the local route from armored key material.
pub fn load_route(armor: &str, pass: &str) -> si_crypto::Result<(opgp::SecretCert, String)> {
    let key = opgp::SecretCert::from_armor(armor, pass)?;
    let id = key
        .public()
        .enc_key_id()
        .ok_or_else(|| si_crypto::Error::Pgp("no subkey".into()))?;
    Ok((key, id))
}
