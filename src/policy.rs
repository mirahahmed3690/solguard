//! The declarative policy: what an agent is allowed to do. Authored as TOML,
//! kept vendor-neutral so it can sit above any wallet/signer.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// Program ids the agent may call. If non-empty, any instruction to a
    /// program NOT in this list is denied (allowlist mode). Empty = no allowlist.
    #[serde(default)]
    pub allowed_programs: Vec<String>,

    /// Program ids that are always denied, even if otherwise allowed.
    #[serde(default)]
    pub blocked_programs: Vec<String>,

    /// Max total native SOL (lamports) movable across the whole transaction.
    #[serde(default)]
    pub max_sol_lamports: Option<u64>,

    /// Per-mint caps on SPL token amount movable across the whole transaction.
    #[serde(default)]
    pub token_caps: Vec<TokenCap>,

    /// If non-empty, every transfer destination (SOL or token) must be listed.
    #[serde(default)]
    pub recipient_allowlist: Vec<String>,

    /// Deny any instruction solguard cannot classify (`Other`). Safe default.
    #[serde(default = "default_true")]
    pub deny_unknown_instructions: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenCap {
    pub mint: String,
    pub max_amount: u64,
}

fn default_true() -> bool {
    true
}

impl Policy {
    pub fn token_cap(&self, mint: &str) -> Option<u64> {
        self.token_caps
            .iter()
            .find(|c| c.mint == mint)
            .map(|c| c.max_amount)
    }

    pub fn recipient_allowed(&self, dest: &str) -> bool {
        self.recipient_allowlist.is_empty() || self.recipient_allowlist.iter().any(|r| r == dest)
    }

    pub fn program_allowed(&self, program: &str) -> bool {
        if self.blocked_programs.iter().any(|p| p == program) {
            return false;
        }
        self.allowed_programs.is_empty() || self.allowed_programs.iter().any(|p| p == program)
    }
}
