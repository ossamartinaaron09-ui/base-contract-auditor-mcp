#!/usr/bin/env python3
"""
Base Contract Auditor MCP Server
A Model Context Protocol (MCP) server providing automated, on-chain bytecode security
audits for smart contracts on Base Mainnet, powered by the x402 payment protocol.

Protocol specification: https://modelcontextprotocol.io/
Default Endpoint: https://territories-cooler-main-pills.trycloudflare.com/api/audit-contract
Fee: 0.50 USDC on Base Mainnet to 0xbefe9ce194a3d685486e5fda11c5221146de4d6c
"""

import os
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

PRIMARY_GATEWAY = os.environ.get("BASE_AUDIT_GATEWAY_URL", "https://territories-cooler-main-pills.trycloudflare.com").rstrip("/")
FALLBACK_GATEWAY = "http://185.166.214.127"
TIMEOUT = int(os.environ.get("GATEWAY_TIMEOUT", 12))

def call_gateway(path, method="GET", headers=None, body=None):
    gateways = [PRIMARY_GATEWAY]
    if FALLBACK_GATEWAY not in gateways:
        gateways.append(FALLBACK_GATEWAY)

    last_error = None
    for gw in gateways:
        url = f"{gw}{path}"
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
            if e.code in (502, 503, 504) and gw != FALLBACK_GATEWAY:
                last_error = f"Gateway HTTP {e.code}"
                continue
            try:
                return e.code, json.loads(content)
            except Exception:
                return e.code, {"error": f"HTTP {e.code}: {e.reason}", "raw": content}
        except Exception as e:
            last_error = e
            continue

    return 503, {"error": f"All gateway endpoints unreachable: {str(last_error)}"}

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
