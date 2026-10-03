# solguard

**A vendor-neutral policy firewall for Solana AI-agent transactions.**

AI agents increasingly hold wallets and send their own on-chain transactions.
`solguard` is the guardrail that runs **before the signature is produced**: give
it a policy (what the agent may do) and the transaction the agent is about to
sign, and it returns **ALLOW** or **DENY** with reasons.

Wallet vendors (Coinbase, Privy, Cobo) each bake spend limits into their own
custody stack. `solguard` is the opposite: a small, open, vendor-neutral layer
that sits above *any* signer and answers one question — *"is this agent allowed
to do this?"* — in a declarative, auditable way.

```
$ solguard check --policy policy.toml --intent intent.json

DENY — 6 violation(s) across 3 instruction(s) for trading-agent-7:
  ix #0 [recipient-not-allowed] token transfer to non-allowlisted recipient Attacker…
  ix #1 [recipient-not-allowed] SOL transfer to non-allowlisted recipient Attacker…
  ix #2 [program-not-allowed]   unclassified call to DrainProg… not in the allowlist
  ix #2 [unknown-instruction]   policy denies unknown instructions
  transaction [sol-cap-exceeded]   total SOL 5.0 > cap 1.0
  transaction [token-cap-exceeded] total USDC 900 > cap 500
# exit code 1
```

## Why

A compromised, jailbroken, or buggy agent will happily sign a wallet-drain. Key
custody alone doesn't stop it — the *signature is authorized*, it's just
authorized for the wrong thing. A policy firewall turns "the agent can sign
anything" into "the agent can sign only what policy permits," and makes that
boundary a file you can review, diff, and version.

## What it checks (v1)

| Rule | Catches |
|------|---------|
| `program-not-allowed` | A call to a program outside the allowlist (or on the blocklist). |
| `recipient-not-allowed` | A SOL/token transfer to an address not on the recipient allowlist. |
| `sol-cap-exceeded` | Total native SOL moved across the tx exceeds the cap. |
| `token-cap-exceeded` | Total of a given mint moved across the tx exceeds its cap. |
| `token-not-capped` | A token transfer of a mint that has no configured cap (while caps exist). |
| `unknown-instruction` | An instruction solguard can't classify, when policy denies unknowns (default). |

Aggregate caps are summed across the whole transaction, so splitting a drain
into several instructions does not dodge a limit.

## Policy (TOML)

```toml
allowed_programs = [
  "11111111111111111111111111111111",            # System
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
]
max_sol_lamports = 1_000_000_000          # 1 SOL / tx
recipient_allowlist = ["SETTLEMENTAcct…"] # transfers only here
deny_unknown_instructions = true          # safe default

[[token_caps]]
mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC
max_amount = 500_000_000                                # 500 USDC
```

> **TOML gotcha:** all top-level keys must come *before* any `[[table]]`
> section, or they're parsed as fields of that table. Keep scalars/arrays first.

## Intent (JSON)

The decoded view of what the agent is about to sign. A real agent runtime
decodes a Solana transaction into this IR (native base64-tx decoding is on the
roadmap); solguard evaluates the IR.

```json
{
  "agent": "trading-agent-7",
  "instructions": [
    { "kind": "token_transfer", "program": "Tokenkeg…", "mint": "EPjF…",
      "from": "Agent…", "to": "SETTLEMENT…", "amount": 250000000, "decimals": 6 }
  ]
}
```

Instruction kinds: `system_transfer`, `token_transfer`, `other` (anything
unclassified — the highest-risk case).

## Usage

```bash
solguard check --policy examples/policy.toml --intent examples/intent_allow.json  # ALLOW, exit 0
solguard check --policy examples/policy.toml --intent examples/intent_deny.json   # DENY,  exit 1
solguard check --policy p.toml --intent i.json --json                              # machine-readable
```

Exit code is `0` for ALLOW and `1` for DENY, so an agent runtime can gate signing
on `solguard` in one line.

## Install

```bash
git clone https://github.com/<you>/solguard
cd solguard
cargo install --path .
```

## Roadmap

- **v2** — native Solana transaction decoding (base64 wire tx → IR) via
  `solana-sdk`; recognise SPL Token-2022, Associated-Token, and common DeFi
  program instruction layouts.
- **v3** — per-source and rate caps (spend-per-hour), simulation hook
  (dry-run the tx and police balance deltas), signed-policy attestation, and a
  long-running daemon mode an agent calls over IPC before each sign.

## License

MIT.
