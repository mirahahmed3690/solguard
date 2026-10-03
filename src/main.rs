//! solguard — a vendor-neutral policy firewall for Solana AI-agent transactions.
//!
//! An agent runtime calls `solguard check` with (1) a policy describing what the
//! agent may do and (2) the decoded transaction intent it is about to sign.
//! solguard returns ALLOW (exit 0) or DENY (exit 1) with reasons — a guardrail
//! that runs BEFORE the signature is produced.

mod engine;
mod intent;
mod policy;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

use engine::{Verdict, Violation};
use intent::Intent;
use policy::Policy;

#[derive(Parser)]
#[command(
    name = "solguard",
    version,
    about = "Policy firewall for Solana agent transactions — ALLOW/DENY before signing"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Evaluate a transaction intent against a policy.
    Check {
        /// Path to the policy file (TOML).
        #[arg(long)]
        policy: PathBuf,
        /// Path to the transaction intent (JSON).
        #[arg(long)]
        intent: PathBuf,
        /// Emit the decision as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Check {
            policy,
            intent,
            json,
        } => run_check(&policy, &intent, json),
    }
}

fn run_check(policy_path: &PathBuf, intent_path: &PathBuf, json: bool) -> ExitCode {
    let policy: Policy = match std::fs::read_to_string(policy_path)
        .map_err(|e| e.to_string())
        .and_then(|s| toml::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to load policy {}: {e}", policy_path.display());
            return ExitCode::from(2);
        }
    };

    let intent: Intent = match std::fs::read_to_string(intent_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!("failed to load intent {}: {e}", intent_path.display());
            return ExitCode::from(2);
        }
    };

    let decision = engine::evaluate(&policy, &intent);

    if json {
        print_json(&decision, &intent);
    } else {
        print_text(&decision, &intent);
    }

    match decision.verdict {
        Verdict::Allow => ExitCode::SUCCESS,
        Verdict::Deny => ExitCode::FAILURE,
    }
}

fn print_text(decision: &engine::Decision, intent: &Intent) {
    let who = if intent.agent.is_empty() {
        "agent".to_string()
    } else {
        intent.agent.clone()
    };
    match decision.verdict {
        Verdict::Allow => {
            println!(
                "{} — {} instruction(s) checked for {who}, no policy violations.",
                "ALLOW".green().bold(),
                decision.checked
            );
        }
        Verdict::Deny => {
            println!(
                "{} — {} violation(s) across {} instruction(s) for {who}:",
                "DENY".red().bold(),
                decision.violations.len(),
                decision.checked
            );
            for vio in &decision.violations {
                let loc = match vio.instruction {
                    Some(i) => format!("ix #{i}"),
                    None => "transaction".to_string(),
                };
                println!("  {} [{}] {}", loc.yellow(), vio.rule.bold(), vio.detail);
            }
        }
    }
}

fn print_json(decision: &engine::Decision, intent: &Intent) {
    // Hand-rolled to avoid deriving Serialize on engine types.
    let verdict = match decision.verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    };
    let vios: Vec<String> = decision
        .violations
        .iter()
        .map(|v: &Violation| {
            format!(
                "{{\"instruction\":{},\"rule\":{},\"detail\":{}}}",
                v.instruction
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "null".into()),
                serde_json::to_string(&v.rule).unwrap(),
                serde_json::to_string(&v.detail).unwrap()
            )
        })
        .collect();
    println!(
        "{{\"verdict\":\"{verdict}\",\"agent\":{},\"checked\":{},\"violations\":[{}]}}",
        serde_json::to_string(&intent.agent).unwrap(),
        decision.checked,
        vios.join(",")
    );
}
