#!/usr/bin/env bash
# Cron wrapper for threat intel data updates.
# Usage in crontab:
#   17 */8 * * * /path/to/threat-intel-dashboard/scripts/cron-update.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_DIR/data/update.log"

cd "$PROJECT_DIR"

# Ensure node is on PATH (nvm, fnm, volta, or system)
for candidate in "$HOME/.local/share/nvm/"v*/bin "$HOME/.nvm/versions/node/"v*/bin "$HOME/.volta/bin" /usr/local/bin; do
  if [ -d "$candidate" ]; then
    export PATH="$candidate:$PATH"
    break
  fi
done

mkdir -p "$(dirname "$LOG_FILE")"

echo "=== Update started at $(date -Iseconds) ===" >> "$LOG_FILE"
npx tsx scripts/update-all.ts >> "$LOG_FILE" 2>&1
echo "=== Update completed at $(date -Iseconds) ===" >> "$LOG_FILE"
