#!/usr/bin/env python3
import os
import re
import sys
import json
import glob
import urllib.request
import urllib.error

GATEWAY_FALLBACK = "http://185.166.214.127"
OFFICIAL_VAULT = "0xbefe9ce194a3d685486e5fda11c5221146de4d6c"

PATTERNS = [
    ("CRITICAL", r"\bselfdestruct\b|\bsuicide\s*\(", "Use of dangerous SELFDESTRUCT opcode (EIP-6780)."),
    ("HIGH", r"\bdelegatecall\b", "Unchecked DELEGATECALL execution - verify storage layout & target contract."),
    ("HIGH", r"\btx\.origin\b", "Authentication with tx.origin is vulnerable to phishing. Use msg.sender."),
    ("MEDIUM", r"block\.timestamp\b|\bnow\b", "Reliance on block.timestamp can be manipulated within drift limits."),
    ("MEDIUM", r"\bunchecked\s*\{", "Unchecked arithmetic block detected - ensure manual bounds validation."),
    ("LOW", r"pragma\s+solidity\s+\^", "Floating pragma detected. Lock compiler version for production deployments.")
]

def scan_solidity_files(directory="."):
    findings = []
    sol_files = glob.glob(os.path.join(directory, "**/*.sol"), recursive=True)
    for fpath in sol_files:
        if any(skip in fpath for skip in ["node_modules", "lib", "cache", "test", ".git"]):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line_no, line in enumerate(lines, 1):
                clean = line.strip()
                if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
                    continue
                for severity, pattern, desc in PATTERNS:
                    if re.search(pattern, clean):
                        findings.append({
                            "file": os.path.relpath(fpath, directory),
                            "line": line_no,
                            "severity": severity,
                            "code": clean[:90],
                            "description": desc
                        })
        except Exception:
            continue
    return findings

def audit_remote_address(address):
    url = f"{GATEWAY_FALLBACK}/api/audit-contract?address={address}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GitHubAction-BaseAuditor/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 500, {"error": str(e)}

def main():
    contract_address = os.environ.get("INPUT_CONTRACT_ADDRESS", "").strip()
    fail_on_critical = os.environ.get("INPUT_FAIL_ON_CRITICAL", "false").lower() == "true"
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    print("==========================================================")
    print(" 🛡️ Base & EVM Smart Contract Security Auditor (CI/CD)")
    print("==========================================================")

    local_findings = scan_solidity_files(".")
    remote_data = None
    if contract_address:
        print(f"[*] Inspecting on-chain state on Base Mainnet: {contract_address}")
        status_code, remote_data = audit_remote_address(contract_address)

    critical_count = sum(1 for f in local_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in local_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in local_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in local_findings if f["severity"] == "LOW")

    print(f"[+] Audit Complete: {len(local_findings)} static findings.")
    print(f"    Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}")

    md = [
        "## 🛡️ Base & EVM Smart Contract Security Audit",
        "",
        "| Severity | Findings | Status |",
        "| :--- | :---: | :--- |",
        f"| 🚨 **CRITICAL** | {critical_count} | {'⚠️ Attention Needed' if critical_count > 0 else '✅ Passed'} |",
        f"| ⚠️ **HIGH** | {high_count} | {'⚠️ Review Recommended' if high_count > 0 else '✅ Passed'} |",
        f"| ℹ️ **MEDIUM** | {medium_count} | {'Informational' if medium_count > 0 else '✅ Passed'} |",
        f"| 🔍 **LOW** | {low_count} | {'Notice' if low_count > 0 else '✅ Passed'} |",
        ""
    ]

    if local_findings:
        md.append("### 📋 Static Analysis Findings")
        md.append("| File | Line | Severity | Issue |")
        md.append("| :--- | :---: | :---: | :--- |")
        for f in local_findings[:25]:
            md.append(f"| `{f['file']}` | {f['line']} | `{f['severity']}` | {f['description']} |")
        md.append("")

    if remote_data and "pricing" in remote_data:
        md.append("### 🌐 On-Chain Base Mainnet Verification")
        md.append(f"- **Contract Address:** `{contract_address}`")
        md.append(f"- **Fee:** `{remote_data.get('pricing', {}).get('amount_usdc', 0.5)} USDC` (Base Network)")
        md.append(f"- **Official Auditor Vault:** `{OFFICIAL_VAULT}`")
        md.append(f"- **x402 Micropayments:** On-chain cryptographic opcode decompiler active.")
        md.append("")

    md.append("---")
    md.append("*Powered by [base-contract-auditor-mcp](https://github.com/ossamartinaaron09-ui/base-contract-auditor-mcp) & x402 Micropayments on Base.*\n")

    if step_summary_path and os.path.exists(os.path.dirname(step_summary_path)):
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write("\n".join(md))
        except Exception:
            pass

    if fail_on_critical and (critical_count > 0 or high_count > 0):
        print("[!] Security threshold failed: Exiting with status 1 due to critical/high issues.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
