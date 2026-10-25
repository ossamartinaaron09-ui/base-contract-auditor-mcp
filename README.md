# Base Contract Auditor MCP Server (`base-contract-auditor-mcp`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Network](https://img.shields.io/badge/Network-Base_Mainnet_(8453)-0052FF.svg)](https://base.org)
[![Protocol](https://img.shields.io/badge/Protocol-Model_Context_Protocol_(MCP)-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![Payment Standard](https://img.shields.io/badge/Payment-x402_Microtransactions-green.svg)](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.3)
[![Auditor Fee](https://img.shields.io/badge/Fee-0.50_USDC-2775CA.svg)](https://basescan.org/address/0xbefe9ce194a3d685486e5fda11c5221146de4d6c)

A production-grade **Model Context Protocol (MCP)** server and CLI client that enables AI assistants (Claude Desktop, Cursor, Windsurf, Antigravity) to perform automated, on-chain bytecode security audits of EVM smart contracts deployed on **Base Mainnet**.

Audits are verified and unlocked on-chain via the **x402 Micropayment Protocol** for **0.50 USDC**.

---

## 🚀 Key Features

- **Bytecode Opcode Security Analysis:** Detects `SELFDESTRUCT` (0xFF) drainage exploits, `DELEGATECALL` (0xF4) proxy logic risks, and deterministic factory (`CREATE2` 0xF5) hazards.
- **Interface & Signature Fingerprinting:** Automatically identifies standard interfaces:
  - ERC-20 Fungible Tokens (`totalSupply`, `balanceOf`, `transfer`, `approve`).
  - ERC-721 Non-Fungible Tokens (`ownerOf`, `balanceOf`).
  - Centralized administrative / owner backdoors (`owner`, `transferOwnership`).
- **Risk Scoring & Classification:** Computes an objective risk score (0-100) and assigns actionable safety verdicts (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`).
- **Universal MCP Compatibility:** Operates seamlessly via stdio JSON-RPC 2.0 with Claude Desktop, Cursor, and any MCP-compliant client.
- **Dual Runtime Support:** Zero external dependencies in Python 3.10+ and Node.js 18+.

---

## 💳 x402 Micropayment Architecture

The audit engine implements the HTTP 402 Payment Required pattern on-chain:

1. **Service Price:** `0.50 USDC` (Base Mainnet).
2. **Official Auditor Vault:**
   ```text
   0xbefe9ce194a3d685486e5fda11c5221146de4d6c
   ```
3. **Official Base USDC Token Contract:**
   ```text
   0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
   ```
4. **Verification Mechanism:** The engine queries Base RPC logs to verify that the specified transaction hash (`X-PAYMENT-TX`) contains an ERC-20 `Transfer` of $\ge 0.50$ USDC to the vault address before returning the cryptographic audit verdict.

---

## 🛠️ MCP Integration Guide

### 1. Claude Desktop Setup

Add the server to your `claude_desktop_config.json`:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

#### Option A: Using Python (Recommended)
```json
{
  "mcpServers": {
    "base-contract-auditor": {
      "command": "python3",
      "args": [
        "/absolute/path/to/base-contract-auditor-mcp/server.py"
      ],
      "env": {
        "BASE_AUDIT_GATEWAY_URL": "http://185.166.214.127:8402"
      }
    }
  }
}
```

#### Option B: Using Node.js
```json
{
  "mcpServers": {
    "base-contract-auditor": {
      "command": "node",
      "args": [
        "/absolute/path/to/base-contract-auditor-mcp/index.js",
        "mcp"
      ],
      "env": {
        "BASE_AUDIT_GATEWAY_URL": "http://185.166.214.127:8402"
      }
    }
  }
}
```

### 2. Cursor / Windsurf Configuration

In Cursor Settings $\to$ Features $\to$ MCP Servers:
- **Name:** `base-contract-auditor`
- **Type:** `command`
- **Command:** `python3 /absolute/path/to/base-contract-auditor-mcp/server.py`

---

## 💻 CLI Usage

You can also run audits directly from your terminal using Python or Node.js without an LLM:

### 1. Check Gateway Status
```bash
# Python
python3 client.py status

# Node.js
node index.js status
```

### 2. Get Payment Information for a Contract
```bash
# Python
python3 client.py info 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913

# Node.js
node index.js info 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
```

### 3. Run a Verified Audit
Once your 0.50 USDC transaction is confirmed on Base:
```bash
# Python
python3 client.py audit 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 --tx 0x4f12ab...

# Node.js
node index.js audit 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 --tx 0x4f12ab...
```

---

## 📊 Sample Output

```json
{
  "payment_status": "VERIFIED_ON_CHAIN",
  "amount_paid_usdc": 0.50,
  "tx_hash": "0x4f12ab...",
  "audit_report": {
    "status": "AUDIT_COMPLETE",
    "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "network": "Base Mainnet (Chain ID 8453)",
    "is_contract": true,
    "bytecode_size_bytes": 2412,
    "native_eth_balance": 0.0,
    "nonce_tx_count": 1,
    "has_selfdestruct": false,
    "has_delegatecall": true,
    "has_create2": false,
    "is_erc20": true,
    "is_erc721": false,
    "risk_score": 30,
    "risk_level": "MEDIUM",
    "findings": [
      "✅ No SELFDESTRUCT opcode found.",
      "🔍 DELEGATECALL opcode detected (0xF4): Proxy / Upgradeable implementation pattern detected. Implementation logic can be redirected by owner/admin.",
      "🪙 Standard ERC-20 Token interface signatures identified (totalSupply, balanceOf, transfer, approve).",
      "👤 Centralized Ownership / Admin functions identified (owner / transferOwnership)."
    ],
    "verdict": "Security Assessment: MEDIUM Risk (Score: 30/100). Review admin and proxy keys carefully."
  }
}
```

---

## 🛡️ Tools Exposed to MCP Clients

| Tool Name | Arguments | Description |
|---|---|---|
| `audit_contract` | `contract_address` (string), `tx_hash` (string) | Executes bytecode analysis and returns comprehensive risk assessment. |
| `get_payment_info` | `contract_address` (optional string) | Returns 0.50 USDC fee, vault recipient, and token contract information. |
| `check_service_status` | *(none)* | Inspects remote gateway uptime and version. |

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
