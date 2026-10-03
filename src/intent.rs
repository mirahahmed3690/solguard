//! The transaction *intent*: a decoded, inspectable view of what an agent is
//! about to sign. A real agent runtime decodes a Solana transaction into this
//! IR (native base64 tx decoding is on the v2 roadmap); solguard then decides
//! ALLOW/DENY against a policy BEFORE the signature is produced.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Intent {
    /// Human label for the agent/session requesting the action (for logs).
    #[serde(default)]
    pub agent: String,
    pub instructions: Vec<Instruction>,
}

/// One instruction, classified into a kind the engine can reason about.
/// Unknown/opaque instructions are represented as `Other` and are the
/// highest-risk case — a policy decides whether to allow them.
// Some fields (`from`, `decimals`, `accounts`) are carried in the IR for use by
// forthcoming rules (per-source caps, decimal-aware limits, account-scope
// checks) and are not all read by v1's rule set yet.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Instruction {
    /// Native SOL transfer via the System program.
    SystemTransfer {
        program: String,
        from: String,
        to: String,
        lamports: u64,
    },
    /// SPL token transfer (Token or Token-2022).
    TokenTransfer {
        program: String,
        mint: String,
        from: String,
        to: String,
        amount: u64,
        #[serde(default)]
        decimals: u8,
    },
    /// Any instruction solguard could not classify.
    Other {
        program: String,
        #[serde(default)]
        accounts: Vec<String>,
        #[serde(default)]
        data_len: usize,
    },
}

impl Instruction {
    pub fn program(&self) -> &str {
        match self {
            Instruction::SystemTransfer { program, .. } => program,
            Instruction::TokenTransfer { program, .. } => program,
            Instruction::Other { program, .. } => program,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Instruction::SystemTransfer { .. } => "system_transfer",
            Instruction::TokenTransfer { .. } => "token_transfer",
            Instruction::Other { .. } => "other",
        }
    }
}
