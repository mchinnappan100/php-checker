#!/usr/bin/env node
/**
 * php-vuln-check.js
 *
 * Checks whether PHP installations are vulnerable to the 2025 critical bugs.
 * Fixed in: 8.5.12, 8.4.27, 8.3.36, 8.2.35
 *
 * Usage:
 *   node php-vuln-check.js                          # check local PHP binary
 *   node php-vuln-check.js --url https://site.com  # check via HTTP headers
 *   node php-vuln-check.js --file hosts.txt        # bulk check URLs (one per line)
 *   node php-vuln-check.js --json                  # output results as JSON
 */

'use strict';
const { execSync } = require('node:child_process');
const { createInterface } = require('node:readline');
const { createReadStream } = require('node:fs');
const https = require('node:https');
const http  = require('node:http');
const path  = require('node:path');

// ── fixed versions per major.minor branch ─────────────────────────────────
const FIXED = {
  '8.5': [8, 5, 12],
  '8.4': [8, 4, 27],
  '8.3': [8, 3, 36],
  '8.2': [8, 2, 35],
};

// ── helpers ───────────────────────────────────────────────────────────────
function parseVersion(str) {
  const m = str && str.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1]), parseInt(m[2]), parseInt(m[3])];
}

function versionString(v) { return v ? v.join('.') : 'unknown'; }

function compare(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return  1;
  }
  return 0;
}

function assess(ver) {
  if (!ver) return { status: 'UNKNOWN', msg: 'Could not determine PHP version' };

  const branch = `${ver[0]}.${ver[1]}`;
  const fixed  = FIXED[branch];

  if (!fixed) {
    if (ver[0] < 8 || (ver[0] === 8 && ver[1] < 2)) {
      return {
        status: 'EOL',
        msg: `PHP ${versionString(ver)} is end-of-life — no security patches will ever be issued. Upgrade to a supported branch immediately.`,
      };
    }
    return {
      status: 'UNKNOWN_BRANCH',
      msg: `PHP ${versionString(ver)} — branch ${branch} is not in the known fix list. Check php.net for advisories.`,
    };
  }

  if (compare(ver, fixed) >= 0) {
    return {
      status: 'SAFE',
      msg: `PHP ${versionString(ver)} is patched (fixed branch minimum: ${versionString(fixed)}).`,
    };
  }

  return {
    status: 'VULNERABLE',
    msg: `PHP ${versionString(ver)} is VULNERABLE. Upgrade to ${versionString(fixed)} or later (branch ${branch}).`,
  };
}

const ICONS = { SAFE: '✅', VULNERABLE: '🚨', EOL: '💀', UNKNOWN: '❓', UNKNOWN_BRANCH: '⚠️' };

function printResult(source, ver, result) {
  const icon = ICONS[result.status] || '❓';
  console.log(`\n${icon}  ${source}`);
  console.log(`   Version : ${versionString(ver) || 'unknown'}`);
  console.log(`   Status  : ${result.status}`);
  console.log(`   ${result.msg}`);
}

// ── check local PHP binary ────────────────────────────────────────────────
function checkLocal() {
  try {
    const out = execSync('php --version 2>&1', { encoding: 'utf8' });
    const ver = parseVersion(out);
    const result = assess(ver);
    printResult('Local PHP (php --version)', ver, result);
    return { source: 'local', version: versionString(ver), ...result };
  } catch {
    console.log('\n❓  Local PHP binary not found or not in PATH.');
    return { source: 'local', version: null, status: 'UNKNOWN', msg: 'php binary not found' };
  }
}

// ── check a URL via HTTP headers ──────────────────────────────────────────
function checkUrl(url) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.request(url, { method: 'HEAD', timeout: 8000 }, (res) => {
      const powered = res.headers['x-powered-by'] || '';
      const server  = res.headers['server'] || '';
      const raw     = powered || server;
      const ver     = parseVersion(raw);
      const result  = assess(ver);

      if (!powered && !parseVersion(server)) {
        console.log(`\n⚠️   ${url}`);
        console.log(`   No PHP version exposed in HTTP headers (X-Powered-By / Server).`);
        console.log(`   This is actually good practice — but you must check the server directly.`);
        resolve({ source: url, version: null, status: 'HEADER_HIDDEN', msg: 'Version not exposed in headers' });
        return;
      }

      printResult(url, ver, result);
      resolve({ source: url, version: versionString(ver), ...result });
    });

    req.on('error', (err) => {
      console.log(`\n❌  ${url}  — connection error: ${err.message}`);
      resolve({ source: url, version: null, status: 'ERROR', msg: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      console.log(`\n❌  ${url}  — timed out`);
      resolve({ source: url, version: null, status: 'TIMEOUT', msg: 'Request timed out' });
    });

    req.end();
  });
}

// ── bulk check from file ──────────────────────────────────────────────────
async function checkFile(filePath) {
  const abs = path.resolve(filePath);
  const rl  = createInterface({ input: createReadStream(abs), crlfDelay: Infinity });
  const results = [];
  for await (const line of rl) {
    const url = line.trim();
    if (!url || url.startsWith('#')) continue;
    results.push(await checkUrl(url));
  }
  return results;
}

// ── summary ───────────────────────────────────────────────────────────────
function printSummary(results) {
  const counts = {};
  results.forEach(r => { counts[r.status] = (counts[r.status] || 0) + 1; });

  console.log('\n─────────────────────────────────────────');
  console.log('SUMMARY');
  console.log('─────────────────────────────────────────');
  Object.entries(counts).forEach(([s, n]) => console.log(`  ${ICONS[s] || '❓'}  ${s}: ${n}`));

  const vuln = results.filter(r => r.status === 'VULNERABLE' || r.status === 'EOL');
  if (vuln.length) {
    console.log('\nSites needing immediate action:');
    vuln.forEach(r => console.log(`  • ${r.source}  (${r.version || 'unknown'})`));
  }

  console.log('\nFixed versions:');
  Object.entries(FIXED).forEach(([b, v]) => console.log(`  PHP ${b}.x  →  upgrade to ${versionString(v)}`));
  console.log('\nReference: https://www.php.net/ChangeLog-8.php');
}

// ── main ──────────────────────────────────────────────────────────────────
(async () => {
  const args    = process.argv.slice(2);
  const jsonOut = args.includes('--json');
  const urlIdx  = args.indexOf('--url');
  const fileIdx = args.indexOf('--file');

  console.log('PHP Vulnerability Checker');
  console.log('Fixed in: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35');
  console.log('─────────────────────────────────────────');

  const results = [];

  if (urlIdx !== -1) {
    const url = args[urlIdx + 1];
    if (!url) { console.error('--url requires a value'); process.exit(1); }
    results.push(await checkUrl(url));

  } else if (fileIdx !== -1) {
    const file = args[fileIdx + 1];
    if (!file) { console.error('--file requires a path'); process.exit(1); }
    results.push(...await checkFile(file));

  } else {
    results.push(checkLocal());
  }

  printSummary(results);

  if (jsonOut) {
    console.log('\nJSON output:');
    console.log(JSON.stringify(results, null, 2));
  }

  const hasVuln = results.some(r => r.status === 'VULNERABLE' || r.status === 'EOL');
  process.exit(hasVuln ? 1 : 0);
})();
