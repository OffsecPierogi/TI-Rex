#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cd "$(dirname "${BASH_SOURCE[0]}")"

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  TI-Rex — Install${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# --- Prerequisites ---

command -v node &>/dev/null || fail "Node.js not found. Install 18+ from https://nodejs.org"
NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
[ "$NODE_VER" -ge 18 ] || fail "Node.js v${NODE_VER} found — need 18+"
ok "Node.js $(node -v)"

command -v npm &>/dev/null || fail "npm not found"
ok "npm $(npm -v)"

command -v git &>/dev/null || fail "git not found"
ok "git $(git --version | awk '{print $3}')"

# --- Environment ---

if [ ! -f .env ]; then
  cp .env.example .env
  ok "Created .env from .env.example"
else
  ok ".env already exists"
fi

if grep -q 'AUTH_SECRET=""' .env 2>/dev/null; then
  SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
  sed -i "s|AUTH_SECRET=\"\"|AUTH_SECRET=\"${SECRET}\"|" .env
  ok "Generated AUTH_SECRET (required for login/registration)"
fi

if grep -q 'NVD_API_KEY=""' .env 2>/dev/null; then
  warn "NVD_API_KEY not set — CVE ingestion will be slow (rate limited)"
  info "Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
fi

# --- PostgreSQL ---

echo ""
echo -e "  TI-Rex requires PostgreSQL."
echo ""
echo "  1) Docker — spin up a local Postgres container (recommended)"
echo "  2) Existing — you already have Postgres running"
echo ""
read -rp "$(echo -e "  ${YELLOW}Choose [1/2]:${NC} ")" db_choice
db_choice="${db_choice:-1}"

if [[ "$db_choice" == "1" ]]; then
  command -v docker &>/dev/null || fail "Docker not installed. Install Docker or choose option 2."
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^tirex-pg$'; then
    ok "tirex-pg container already running"
  else
    docker rm -f tirex-pg 2>/dev/null || true
    docker run -d --name tirex-pg \
      -e POSTGRES_USER=tirex \
      -e POSTGRES_PASSWORD=tirex \
      -e POSTGRES_DB=tirex \
      -v tirex-pgdata:/var/lib/postgresql/data \
      -p 5432:5432 \
      postgres:16-alpine
    echo -n "  Waiting for Postgres..."
    for i in $(seq 1 15); do
      if docker exec tirex-pg pg_isready -U tirex &>/dev/null; then break; fi
      sleep 1; echo -n "."
    done
    echo ""
    ok "PostgreSQL container started"
  fi
else
  info "Using existing PostgreSQL — make sure DATABASE_URL in .env is correct"
fi

# --- Dependencies ---

echo ""
info "Installing dependencies..."
npm install --loglevel=warn
ok "Dependencies installed"

# --- Database ---

info "Setting up database..."
npx prisma generate
npx prisma migrate deploy 2>/dev/null || npx prisma db push --accept-data-loss
ok "Database schema applied"

# --- Data ingestion ---

echo ""
echo "  The next step downloads threat intel data from MITRE ATT&CK,"
echo "  CISA KEV, abuse.ch, SigmaHQ, and other public sources."
echo "  Fast mode takes ~2 minutes. Full mode takes 10-15 minutes."
echo ""
read -rp "$(echo -e "  ${YELLOW}Ingest threat data now? [Y/n]:${NC} ")" ingest
ingest="${ingest:-Y}"

if [[ "$ingest" =~ ^[Yy]$ ]]; then
  echo ""
  echo "  1) Fast — core data only (~2 min), slow enrichment runs automatically later"
  echo "  2) Full — everything including NVD/Malpedia (10-15 min)"
  echo ""
  read -rp "$(echo -e "  ${YELLOW}Choose [1/2]:${NC} ")" speed
  speed="${speed:-1}"

  if [[ "$speed" == "2" ]]; then
    info "Running full data pipeline (31 steps)..."
    npx tsx scripts/update-all.ts
  else
    info "Running fast install (skipping slow API enrichment)..."
    npx tsx scripts/update-all.ts --fast
  fi
  ok "Data ingestion complete"
else
  info "Skipped. Run later with: npx tsx scripts/update-all.ts"
fi

# --- Build & start ---

echo ""
info "Building production bundle..."
npm run build
ok "Build complete"

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${GREEN}${BOLD}  Install complete${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""
echo -e "  Start the app:"
echo -e "    ${CYAN}npm run dev${NC}                  (development)"
echo -e "    ${CYAN}npm start${NC}                    (production)"
echo ""
echo -e "  Open ${CYAN}http://localhost:3000/register${NC}"
echo -e "  First user becomes Admin."
echo ""
echo -e "  Data auto-refreshes every 6 hours (configurable in Settings)."
echo -e "  Manual refresh: ${CYAN}npx tsx scripts/update-all.ts${NC}"
echo ""
