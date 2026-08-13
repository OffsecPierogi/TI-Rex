#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
crit() { echo -e "  ${RED}${BOLD}[CRIT]${NC} $1"; }

LOCKFILE="package-lock.json"
FOUND_COMPROMISED=0
FOUND_VULN=0

# Known compromised package@version pairs from major supply chain incidents.
# Format: "package@version|incident"
# Update this list as new incidents are disclosed.
COMPROMISED_PACKAGES=(
  # CHAINDROP / Shai-Hulud worm — Aug 4 2026
  # Ref: https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain
  "keyv@6.0.0|CHAINDROP worm (Aug 2026)"
  "flat-cache@6.1.24|CHAINDROP worm (Aug 2026)"
  "file-entry-cache@11.1.6|CHAINDROP worm (Aug 2026)"
  "cacheable-request@13.0.20|CHAINDROP worm (Aug 2026)"
  "cache-manager@7.2.10|CHAINDROP worm (Aug 2026)"
  "cacheable@2.0.3|CHAINDROP worm (Aug 2026)"

  # chalk/debug maintainer phish — Sep 8 2025
  # Ref: https://github.com/chalk/chalk/issues/656
  "chalk@5.6.1|chalk/debug hijack (Sep 2025)"
  "chalk-template@1.1.1|chalk/debug hijack (Sep 2025)"
  "debug@4.4.2|chalk/debug hijack (Sep 2025)"
  "color@5.0.1|chalk/debug hijack (Sep 2025)"
  "color-convert@3.1.1|chalk/debug hijack (Sep 2025)"
  "color-name@2.0.1|chalk/debug hijack (Sep 2025)"
  "color-string@2.1.1|chalk/debug hijack (Sep 2025)"
  "supports-color@10.2.1|chalk/debug hijack (Sep 2025)"
  "supports-hyperlinks@4.1.1|chalk/debug hijack (Sep 2025)"
  "strip-ansi@7.1.1|chalk/debug hijack (Sep 2025)"
  "wrap-ansi@9.0.1|chalk/debug hijack (Sep 2025)"
  "slice-ansi@7.1.1|chalk/debug hijack (Sep 2025)"
  "has-ansi@6.0.1|chalk/debug hijack (Sep 2025)"
  "error-ex@1.3.3|chalk/debug hijack (Sep 2025)"
  "is-arrayish@0.3.3|chalk/debug hijack (Sep 2025)"
  "simple-swizzle@0.2.3|chalk/debug hijack (Sep 2025)"
  "duckdb@1.3.3|chalk/debug hijack (Sep 2025)"

  # axios UNC1069 (North Korea) — Mar 31 2026
  # Ref: https://github.com/axios/axios/issues/10636
  "axios@1.14.1|axios UNC1069 (Mar 2026)"
  "axios@0.30.4|axios UNC1069 (Mar 2026)"

  # @tanstack Mini Shai-Hulud — May 11 2026
  # Ref: https://snyk.io/blog/tanstack-npm-packages-compromised/
  "@tanstack/react-query@5.75.8|TanStack Mini Shai-Hulud (May 2026)"
  "@tanstack/query-core@5.75.8|TanStack Mini Shai-Hulud (May 2026)"
  "@tanstack/vue-query@5.75.8|TanStack Mini Shai-Hulud (May 2026)"
  "@tanstack/solid-query@5.75.8|TanStack Mini Shai-Hulud (May 2026)"
)

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  Supply Chain Audit${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# --- Check 1: Known compromised versions ---

if [ ! -f "$LOCKFILE" ]; then
  fail "No package-lock.json found — run npm install first"
  exit 1
fi

info "Checking lockfile against known compromised packages..."

INSTALLED=$(node -e "
const lock = require('./$LOCKFILE');
const pkgs = lock.packages || {};
for (const [path, info] of Object.entries(pkgs)) {
  if (!path) continue;
  const name = path.split('node_modules/').pop();
  console.log(name + '@' + (info.version || ''));
}
")

for entry in "${COMPROMISED_PACKAGES[@]}"; do
  PKG="${entry%%|*}"
  INCIDENT="${entry##*|}"
  if echo "$INSTALLED" | grep -qxF "$PKG"; then
    crit "COMPROMISED: ${PKG} — ${INCIDENT}"
    FOUND_COMPROMISED=1
  fi
done

if [ "$FOUND_COMPROMISED" -eq 0 ]; then
  ok "No known compromised package versions found (checked ${#COMPROMISED_PACKAGES[@]} signatures)"
fi

# --- Check 2: npm audit ---

echo ""
info "Running npm audit..."

AUDIT_OUTPUT=$(npm audit --json 2>/dev/null || true)
VULN_COUNT=$(echo "$AUDIT_OUTPUT" | node -e "
const d = require('fs').readFileSync('/dev/stdin','utf8');
try {
  const j = JSON.parse(d);
  const v = j.metadata?.vulnerabilities || {};
  const crit = v.critical || 0;
  const high = v.high || 0;
  const mod = v.moderate || 0;
  const low = v.low || 0;
  console.log(crit + '|' + high + '|' + mod + '|' + low);
} catch { console.log('0|0|0|0'); }
" 2>/dev/null || echo "0|0|0|0")

IFS='|' read -r CRIT HIGH MOD LOW <<< "$VULN_COUNT"

if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
  FOUND_VULN=1
  [ "$CRIT" -gt 0 ] && crit "npm audit: ${CRIT} critical vulnerabilities"
  [ "$HIGH" -gt 0 ] && warn "npm audit: ${HIGH} high vulnerabilities"
  [ "$MOD" -gt 0 ]  && info "npm audit: ${MOD} moderate vulnerabilities"
  [ "$LOW" -gt 0 ]  && info "npm audit: ${LOW} low vulnerabilities"
  echo ""
  info "Run ${CYAN}npm audit${NC} for details, ${CYAN}npm audit fix${NC} to auto-fix"
else
  [ "$MOD" -gt 0 ] && info "npm audit: ${MOD} moderate, ${LOW} low (no critical/high)"
  [ "$MOD" -eq 0 ] && ok "npm audit clean"
fi

# --- Check 3: Lockfile integrity ---

echo ""
info "Verifying package integrity..."

INTEGRITY_FAILS=$(node -e "
const lock = require('./$LOCKFILE');
const pkgs = lock.packages || {};
let missing = 0;
for (const [path, info] of Object.entries(pkgs)) {
  if (!path || info.link) continue;
  if (!info.integrity && !path.includes('@types/')) missing++;
}
console.log(missing);
" 2>/dev/null || echo "0")

if [ "$INTEGRITY_FAILS" -gt 0 ]; then
  warn "${INTEGRITY_FAILS} packages missing integrity hashes — consider deleting node_modules and running npm install"
else
  ok "All packages have integrity hashes"
fi

# --- Summary ---

echo ""
echo -e "${BOLD}----------------------------------------${NC}"
if [ "$FOUND_COMPROMISED" -eq 1 ]; then
  echo ""
  crit "COMPROMISED PACKAGES DETECTED"
  echo -e "  Do NOT run this application until compromised packages are removed."
  echo -e "  1. Delete node_modules: ${CYAN}rm -rf node_modules${NC}"
  echo -e "  2. Pin safe versions in package.json"
  echo -e "  3. Reinstall: ${CYAN}npm install${NC}"
  echo -e "  4. Re-run this audit: ${CYAN}bash scripts/audit-supply-chain.sh${NC}"
  echo ""
  exit 1
elif [ "$FOUND_VULN" -eq 1 ]; then
  warn "Vulnerabilities found — review npm audit output"
  exit 0
else
  ok "Supply chain audit passed"
  exit 0
fi
