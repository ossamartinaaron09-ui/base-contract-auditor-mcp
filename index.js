#!/usr/bin/env node
/**
 * Base Contract Auditor MCP Server & Client (Node.js)
 * Model Context Protocol (MCP) tool provider for on-chain Base smart contract security audits.
 * Powered by x402 payment standard.
 */

const http = require('http');
const https = require('https');
const url = require('url');
const readline = require('readline');

const GATEWAY_URL = process.env.BASE_AUDIT_GATEWAY_URL || 'http://185.166.214.127';

function requestGateway(path, options = {}) {
  return new Promise((resolve, reject) => {
    const fullUrl = `${GATEWAY_URL}${path}`;
    const parsed = new URL(fullUrl);
    const client = parsed.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'BaseContractAuditorMCP-Node/1.0.0',
        ...(options.headers || {})
      },
      timeout: 20000
    };

    const req = client.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data: { raw: data, error: 'Non-JSON response' } });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 504, data: { error: 'Gateway timeout' } });
    });

    req.on('error', (err) => {
      resolve({ status: 503, data: { error: `Connection failed: ${err.message}` } });
    });

    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    req.end();
  });
}

const TOOLS = [
  {
    name: 'audit_contract',
    description: 'Performs an on-chain bytecode security audit of a smart contract on Base Mainnet. Checks for SELFDESTRUCT opcodes, DELEGATECALL proxies, ERC-20/721 interfaces, centralized owner selectors, and calculates a risk score. Requires a confirmed 0.50 USDC transfer on Base.',
    inputSchema: {
      type: 'object',
      properties: {
        contract_address: {
          type: 'string',
          description: 'The 42-character 0x EVM smart contract address on Base Mainnet to audit.'
        },
        tx_hash: {
          type: 'string',
          description: 'The 66-character 0x transaction hash on Base confirming the 0.50 USDC payment to the auditor vault (0xbefe9ce194a3d685486e5fda11c5221146de4d6c).'
        }
      },
      required: ['contract_address', 'tx_hash']
    }
  },
  {
    name: 'get_payment_info',
    description: 'Retrieves the x402 payment parameters required to unlock a contract audit: fee (0.50 USDC), Base vault address, and official Base USDC contract.',
    inputSchema: {
      type: 'object',
      properties: {
        contract_address: {
          type: 'string',
          description: 'Optional smart contract address you plan to audit.'
        }
      }
    }
  },
  {
    name: 'check_service_status',
    description: 'Checks the operational status, version, and endpoints of the Base Audit Gateway.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }
];

async function handleRpc(req) {
  const { id, method, params } = req;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'base-contract-auditor-mcp', version: '1.0.0' }
      }
    };
  }

  if (method === 'notifications/initialized') {
    return null;
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }

  if (method === 'tools/call') {
    const { name, arguments: args } = params;
    let resData;

    if (name === 'audit_contract') {
      const { contract_address, tx_hash } = args || {};
      if (!contract_address || !tx_hash) {
        resData = { error: 'Both contract_address and tx_hash are required.' };
      } else {
        const resp = await requestGateway(`/api/audit-contract?address=${encodeURIComponent(contract_address)}`, {
          headers: { 'X-PAYMENT-TX': tx_hash }
        });
        resData = resp.data;
      }
    } else if (name === 'get_payment_info') {
      const addr = (args && args.contract_address) ? encodeURIComponent(args.contract_address) : '';
      const resp = await requestGateway(addr ? `/api/audit-contract?address=${addr}` : '/api/audit-contract');
      resData = resp.data;
    } else if (name === 'check_service_status') {
      const resp = await requestGateway('/status');
      resData = resp.data;
    } else {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Tool not found: ${name}` }
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      result: {
        content: [{ type: 'text', text: JSON.stringify(resData, null, 2) }]
      }
    };
  }

  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not supported: ${method}` }
  };
}

// CLI Mode vs MCP Server Mode
const args = process.argv.slice(2);
if (args.length > 0 && args[0] !== 'mcp') {
  const cmd = args[0];
  if (cmd === 'status') {
    requestGateway('/status').then(r => console.log(JSON.stringify(r.data, null, 2)));
  } else if (cmd === 'info') {
    const addr = args[1] ? `?address=${encodeURIComponent(args[1])}` : '';
    requestGateway(`/api/audit-contract${addr}`).then(r => console.log(JSON.stringify(r.data, null, 2)));
  } else if (cmd === 'audit') {
    const addr = args[1];
    const txIndex = args.indexOf('--tx');
    const txHash = txIndex !== -1 ? args[txIndex + 1] : null;
    if (!addr || !txHash) {
      console.error('Usage: node index.js audit <contract_address> --tx <tx_hash>');
      process.exit(1);
    }
    requestGateway(`/api/audit-contract?address=${encodeURIComponent(addr)}`, {
      headers: { 'X-PAYMENT-TX': txHash }
    }).then(r => console.log(JSON.stringify(r.data, null, 2)));
  } else {
    console.error('Unknown command. Use: status, info [contract], audit <contract> --tx <hash>, or run without args for MCP server.');
  }
} else {
  // Stdio MCP Server
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('line', async (line) => {
    line = line.trim();
    if (!line) return;
    try {
      const parsed = JSON.parse(line);
      const resp = await handleRpc(parsed);
      if (resp) {
        process.stdout.write(JSON.stringify(resp) + '\n');
      }
    } catch (e) {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32603, message: `JSON parse error: ${e.message}` }
      }) + '\n');
    }
  });
}
