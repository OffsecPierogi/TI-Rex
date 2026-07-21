#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

section() {
  echo ""
  echo -e "${BOLD}--- $1 ---${NC}"
}

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

# ---------------------------------------------------------------------------
#  Banner
# ---------------------------------------------------------------------------

echo ""
echo -e "${BOLD}======================================================${NC}"
echo -e "${BOLD}  TI-Rex -- Threat Intelligence Platform Setup${NC}"
echo -e "${BOLD}  MITRE ATT&CK  |  Atomic Red Team  |  IOCs${NC}"
echo -e "${BOLD}======================================================${NC}"

# ---------------------------------------------------------------------------
#  Prerequisites
# ---------------------------------------------------------------------------

section "Checking prerequisites"

missing=0

if ! command -v node &>/dev/null; then
  fail "Node.js not found"
  echo "       Install Node.js 18+ from https://nodejs.org or via nvm:"
  echo "       curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash"
  echo "       nvm install 20"
  missing=1
else
  NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
  if [ "$NODE_VER" -lt 18 ]; then
    fail "Node.js v${NODE_VER} found -- need 18+"
    missing=1
  else
    ok "Node.js $(node -v)"
  fi
fi

if ! command -v npm &>/dev/null; then
  fail "npm not found"
  missing=1
else
  ok "npm $(npm -v)"
fi

if ! command -v git &>/dev/null; then
  fail "git not found (required for MITRE/Atomic data cloning)"
  missing=1
else
  ok "git $(git --version | awk '{print $3}')"
fi

if ! command -v docker &>/dev/null; then
  warn "Docker not found (optional -- needed for Docker Compose deployment)"
else
  ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
fi

if [ "$missing" -eq 1 ]; then
  echo ""
  echo -e "${RED}Missing prerequisites. Install them and re-run this script.${NC}"
  exit 1
fi

# ---------------------------------------------------------------------------
#  Environment file
# ---------------------------------------------------------------------------

section "Environment configuration"

if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    ok "Created .env from .env.example"
  else
    echo 'DATABASE_URL="postgresql://tirex:tirex@localhost:5432/tirex"' > .env
    echo 'AUTH_SECRET=""' >> .env
    warn ".env.example not found -- created minimal .env"
  fi
fi

# Generate AUTH_SECRET if empty
if grep -q 'AUTH_SECRET=""' .env 2>/dev/null; then
  SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
  sed -i "s|AUTH_SECRET=\"\"|AUTH_SECRET=\"${SECRET}\"|" .env
  ok "Generated AUTH_SECRET (required for login/registration)"
else
  ok ".env already configured"
fi

if grep -q 'NVD_API_KEY=""' .env 2>/dev/null; then
  warn "NVD_API_KEY not set -- CVE ingestion will be slow (rate limited)"
  info "Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
fi

info "Edit .env to add API keys (optional -- works without them)"

# ---------------------------------------------------------------------------
#  Database setup
# ---------------------------------------------------------------------------

section "Database setup"

echo ""
echo "  TI-Rex requires PostgreSQL. Choose how to set it up:"
echo ""
echo "  1) Docker (recommended) -- starts a local Postgres container"
echo "  2) Manual -- you already have Postgres running (edit DATABASE_URL in .env)"
echo ""

read -rp "$(echo -e "  ${YELLOW}Choose [1/2]:${NC} ")" db_choice
db_choice="${db_choice:-1}"

if [[ "$db_choice" == "1" ]]; then
  if command -v docker &>/dev/null; then
    if docker ps --format '{{.Names}}' | grep -q '^tirex-pg$'; then
      ok "PostgreSQL container already running"
    else
      docker run -d --name tirex-pg \
        -e POSTGRES_USER=tirex \
        -e POSTGRES_PASSWORD=tirex \
        -e POSTGRES_DB=tirex \
        -v tirex-pgdata:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres:16-alpine
      sleep 3
      ok "PostgreSQL container started"
    fi
  else
    fail "Docker not installed. Install Docker or use option 2."
    exit 1
  fi
else
  info "Using existing PostgreSQL. Make sure DATABASE_URL in .env is correct."
fi

# ---------------------------------------------------------------------------
#  Dependencies
# ---------------------------------------------------------------------------

section "Installing dependencies"

npm install
ok "Dependencies installed"

# ---------------------------------------------------------------------------
#  Schema migration
# ---------------------------------------------------------------------------

section "Applying database migrations"

npx prisma generate
npx prisma migrate deploy
ok "Database schema ready"

# ---------------------------------------------------------------------------
#  Data ingestion (optional)
# ---------------------------------------------------------------------------

section "Threat intelligence data"

echo ""
echo "  The next step clones MITRE ATT&CK and Atomic Red Team repos,"
echo "  then parses and ingests all threat intel data into the database."
echo "  This takes 2-5 minutes and requires an internet connection."
echo ""

read -rp "$(echo -e "  ${YELLOW}Download and ingest threat data now? [Y/n]:${NC} ")" ingest_choice
ingest_choice="${ingest_choice:-Y}"

if [[ "$ingest_choice" =~ ^[Yy]$ ]]; then
  echo ""
  info "Starting data ingestion..."
  npx tsx scripts/update-all.ts
  ok "Data ingestion complete"
else
  echo ""
  info "Skipped. You can ingest data later by running:"
  echo "       npx tsx scripts/update-all.ts"
fi

# ---------------------------------------------------------------------------
#  Done
# ---------------------------------------------------------------------------

echo ""
echo -e "${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD}  Setup complete${NC}"
echo -e "${BOLD}======================================================${NC}"
echo ""
echo "  Start the dashboard:"
echo -e "    ${CYAN}npm run dev${NC}"
echo ""
echo "  Then open:"
echo -e "    ${CYAN}http://localhost:3000/register${NC}"
echo "  The first user to register becomes Admin."
echo ""
echo "  Docker Compose (alternative):"
echo -e "    ${CYAN}docker compose up --build${NC}"
echo ""
echo "  Other commands:"
echo -e "    ${CYAN}npm run update${NC}              Refresh all threat data"
echo -e "    ${CYAN}npm run build && npm start${NC}  Production build"
echo ""
