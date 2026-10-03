//! The decision engine: evaluate an `Intent` against a `Policy`, returning a
//! verdict plus the list of violations (reasons). Aggregate caps (SOL total,
//! per-mint token totals) are summed across all instructions so a transaction
//! can't dodge a cap by splitting into several instructions.

use std::collections::HashMap;

use crate::intent::{Instruction, Intent};
use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Violation {
    /// Index of the offending instruction, or None for a whole-tx (aggregate) rule.
    pub instruction: Option<usize>,
    pub rule: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub violations: Vec<Violation>,
    pub checked: usize,
}

pub fn evaluate(policy: &Policy, intent: &Intent) -> Decision {
    let mut v: Vec<Violation> = Vec::new();

    // Per-instruction checks.
    for (i, ix) in intent.instructions.iter().enumerate() {
        // Program allow/block list.
        if !policy.program_allowed(ix.program()) {
            v.push(Violation {
                instruction: Some(i),
                rule: "program-not-allowed".into(),
                detail: format!(
                    "{} calls program {} which is blocked or not in the allowlist",
                    ix.kind_label(),
                    ix.program()
                ),
            });
        }

        match ix {
            Instruction::SystemTransfer { to, lamports, .. } => {
                if !policy.recipient_allowed(to) {
                    v.push(Violation {
                        instruction: Some(i),
                        rule: "recipient-not-allowed".into(),
                        detail: format!("SOL transfer to non-allowlisted recipient {to}"),
                    });
                }
                if *lamports == 0 {
                    v.push(Violation {
                        instruction: Some(i),
                        rule: "zero-amount".into(),
                        detail: "SOL transfer of 0 lamports".into(),
                    });
                }
            }
            Instruction::TokenTransfer {
                mint, to, amount, ..
            } => {
                if !policy.recipient_allowed(to) {
                    v.push(Violation {
                        instruction: Some(i),
                        rule: "recipient-not-allowed".into(),
                        detail: format!("token transfer to non-allowlisted recipient {to}"),
                    });
                }
                // A mint with no configured cap, while caps exist, is suspicious.
                if !policy.token_caps.is_empty() && policy.token_cap(mint).is_none() {
                    v.push(Violation {
                        instruction: Some(i),
                        rule: "token-not-capped".into(),
                        detail: format!("transfer of un-capped mint {mint} (amount {amount})"),
                    });
                }
            }
            Instruction::Other {
                program, data_len, ..
            } => {
                if policy.deny_unknown_instructions {
                    v.push(Violation {
                        instruction: Some(i),
                        rule: "unknown-instruction".into(),
                        detail: format!(
                            "unclassified instruction to {program} ({data_len} bytes data) — \
                             policy denies unknown instructions"
                        ),
                    });
                }
            }
        }
    }

    // Aggregate checks (summed across the whole transaction).
    let mut sol_total: u128 = 0;
    let mut token_totals: HashMap<&str, u128> = HashMap::new();
    for ix in &intent.instructions {
        match ix {
            Instruction::SystemTransfer { lamports, .. } => sol_total += *lamports as u128,
            Instruction::TokenTransfer { mint, amount, .. } => {
                *token_totals.entry(mint.as_str()).or_default() += *amount as u128
            }
            Instruction::Other { .. } => {}
        }
    }

    if let Some(max) = policy.max_sol_lamports {
        if sol_total > max as u128 {
            v.push(Violation {
                instruction: None,
                rule: "sol-cap-exceeded".into(),
                detail: format!(
                    "total SOL moved {sol_total} lamports exceeds cap {max}"
                ),
            });
        }
    }

    for (mint, total) in &token_totals {
        if let Some(cap) = policy.token_cap(mint) {
            if *total > cap as u128 {
                v.push(Violation {
                    instruction: None,
                    rule: "token-cap-exceeded".into(),
                    detail: format!(
                        "total {mint} moved {total} exceeds cap {cap}"
                    ),
                });
            }
        }
    }

    let verdict = if v.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Deny
    };

    Decision {
        verdict,
        violations: v,
        checked: intent.instructions.len(),
    }
}
