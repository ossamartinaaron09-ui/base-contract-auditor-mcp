#!/usr/bin/env python3
"""
Base Contract Auditor MCP Server
A Model Context Protocol (MCP) server providing automated, on-chain bytecode security
audits for smart contracts on Base Mainnet, powered by the x402 payment protocol.

Protocol specification: https://modelcontextprotocol.io/
Default Endpoint: http://185.166.214.127/api/audit-contract
Fee: 0.50 USDC on Base Mainnet to 0xbefe9ce194a3d685486e5fda11c5221146de4d6c
"""

import os
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

GATEWAY_URL = os.environ.get("BASE_AUDIT_GATEWAY_URL", "http://185.166.214.127").rstrip("/")
TIMEOUT = int(os.environ.get("GATEWAY_TIMEOUT", 20))

def call_gateway(path, method="GET", headers=None, body=None):
    url = f"{GATEWAY_URL}{path}"
    req_headers = {"User-Agent": "BaseContractAuditorMCP/1.0.0"}
    if headers:
        req_headers.update(headers)
    
    data = json.dumps(body).encode("utf-8") if body else None
    if body and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content)
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, {"error": f"HTTP {e.code}: {e.reason}", "raw": content}
    except Exception as e:
        return 503, {"error": f"Gateway unreachable at {GATEWAY_URL}: {str(e)}"}

def tool_get_payment_info(arguments):
    contract_addr = arguments.get("contract_address", "")
    path = f"/api/audit-contract?address={urllib.parse.quote(contract_addr)}" if contract_addr else "/api/audit-contract"
    code, data = call_gateway(path, method="GET")
    
    # Static fallback info if gateway returns connection error
    if code == 503:
        return {
            "protocol": "x402-v1",
            "service": "Smart Contract Bytecode Audit (Base)",
            "target_contract": contract_addr,
            "price_usdc": 0.50,
            "accepted_token": "USDC (Base Mainnet)",
            "vault_evm_base": "0xbefe9ce194a3d685486e5fda11c5221146de4d6c",
            "usdc_contract_base": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "instruction": "Send 0.50 USDC on Base to vault_evm_base (0xbefe9ce194a3d685486e5fda11c5221146de4d6c) and supply the transaction hash to audit_contract."
        }
    return data

def tool_audit_contract(arguments):
    contract_addr = arguments.get("contract_address", "").strip()
    tx_hash = arguments.get("tx_hash", "").strip()

    if not contract_addr or not contract_addr.startswith("0x") or len(contract_addr) != 42:
        return {"error": "Invalid EVM contract address format. Must be a 42-character hex string starting with 0x."}

    if not tx_hash or not tx_hash.startswith("0x") or len(tx_hash) != 66:
        return {
            "error": "Invalid or missing transaction hash.",
            "instruction": "Provide the 66-character Base transaction hash (starting with 0x) of your 0.50 USDC transfer to 0xbefe9ce194a3d685486e5fda11c5221146de4d6c."
        }

    path = f"/api/audit-contract?address={urllib.parse.quote(contract_addr)}"
    headers = {"X-PAYMENT-TX": tx_hash}
    code, data = call_gateway(path, method="GET", headers=headers)
    return data

def tool_check_status(arguments):
    code, data = call_gateway("/status", method="GET")
    return data

TOOLS = [
    {
        "name": "audit_contract",
        "description": "Performs an on-chain bytecode security audit of a smart contract on Base Mainnet. Checks for SELFDESTRUCT opcodes, DELEGATECALL proxies, ERC-20/721 interfaces, centralized owner selectors, and calculates a risk score. Requires a confirmed 0.50 USDC transfer on Base.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "contract_address": {
                    "type": "string",
                    "description": "The 42-character 0x EVM smart contract address on Base Mainnet to audit."
                },
                "tx_hash": {
                    "type": "string",
                    "description": "The 66-character 0x transaction hash on Base confirming the 0.50 USDC payment to the auditor vault (0xbefe9ce194a3d685486e5fda11c5221146de4d6c)."
                }
            },
            "required": ["contract_address", "tx_hash"]
        }
    },
    {
        "name": "get_payment_info",
        "description": "Retrieves the x402 payment parameters required to unlock a contract audit: fee (0.50 USDC), Base vault address, and official Base USDC contract.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "contract_address": {
                    "type": "string",
                    "description": "Optional smart contract address you plan to audit."
                }
            }
        }
    },
    {
        "name": "check_service_status",
        "description": "Checks the operational status, version, and endpoints of the Base Audit Gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

def handle_jsonrpc(req):
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "base-contract-auditor-mcp",
                    "version": "1.0.0"
                }
            }
        }

    elif method == "notifications/initialized":
        return None

    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if tool_name == "audit_contract":
            res = tool_audit_contract(tool_args)
        elif tool_name == "get_payment_info":
            res = tool_get_payment_info(tool_args)
        elif tool_name == "check_service_status":
            res = tool_check_status(tool_args)
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Tool not found: {tool_name}"
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(res, indent=2)
                    }
                ]
            }
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not supported: {method}"
            }
        }

def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            req = json.loads(line)
            resp = handle_jsonrpc(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
