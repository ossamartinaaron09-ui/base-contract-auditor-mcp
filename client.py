#!/usr/bin/env python3
"""
Base Contract Auditor - Python Client & SDK
Connects to the x402 on-chain smart contract security auditor gateway.

Usage CLI:
    python client.py status
    python client.py info 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
    python client.py audit 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 --tx 0x...
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
import urllib.parse

DEFAULT_GATEWAY = os.environ.get("BASE_AUDIT_GATEWAY_URL", "http://185.166.214.127").rstrip("/")

class BaseAuditorClient:
    def __init__(self, gateway_url=None, timeout=20):
        self.gateway_url = (gateway_url or DEFAULT_GATEWAY).rstrip("/")
        self.timeout = timeout

    def _request(self, path, method="GET", headers=None, body=None):
        url = f"{self.gateway_url}{path}"
        req_headers = {"User-Agent": "BaseAuditorClient/1.0.0"}
        if headers:
            req_headers.update(headers)

        data = json.dumps(body).encode("utf-8") if body else None
        if body and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"error": f"HTTP {e.code}", "detail": raw}
        except Exception as e:
            return 503, {"error": f"Connection failed to {self.gateway_url}: {str(e)}"}

    def get_status(self):
        """Returns the gateway health and service directory."""
        return self._request("/status")

    def get_payment_info(self, contract_address=""):
        """Returns payment details and requirements (x402 protocol)."""
        path = f"/api/audit-contract?address={urllib.parse.quote(contract_address)}" if contract_address else "/api/audit-contract"
        return self._request(path)

    def audit_contract(self, contract_address, tx_hash):
        """
        Submits smart contract for security audit with the verified payment transaction hash.
        Cost: 0.50 USDC on Base.
        """
        path = f"/api/audit-contract?address={urllib.parse.quote(contract_address)}"
        headers = {"X-PAYMENT-TX": tx_hash}
        return self._request(path, headers=headers)

def main():
    parser = argparse.ArgumentParser(description="Base Contract Auditor CLI (x402 Microservices)")
    parser.add_argument("--gateway", default=None, help=f"Gateway URL (default: {DEFAULT_GATEWAY})")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status command
    subparsers.add_parser("status", help="Check gateway operational status")

    # info command
    info_p = subparsers.add_parser("info", help="Get payment requirements and instructions")
    info_p.add_argument("contract", nargs="?", default="", help="Optional contract address")

    # audit command
    audit_p = subparsers.add_parser("audit", help="Run smart contract bytecode audit")
    audit_p.add_argument("contract", help="Contract address on Base to audit")
    audit_p.add_argument("--tx", required=True, help="Base transaction hash of 0.50 USDC payment")

    args = parser.parse_args()
    client = BaseAuditorClient(gateway_url=args.gateway)

    if args.command == "status":
        code, data = client.get_status()
        print(json.dumps(data, indent=2))
        sys.exit(0 if code == 200 else 1)

    elif args.command == "info":
        code, data = client.get_payment_info(args.contract)
        print(json.dumps(data, indent=2))
        sys.exit(0 if code in [200, 402] else 1)

    elif args.command == "audit":
        code, data = client.audit_contract(args.contract, args.tx)
        print(json.dumps(data, indent=2))
        sys.exit(0 if code == 200 else 1)

if __name__ == "__main__":
    main()
