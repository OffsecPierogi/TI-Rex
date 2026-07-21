#!/bin/bash
set -e

export NODE_PATH="$(npm root -g):${NODE_PATH:-}"

echo "Running database migrations..."
prisma migrate deploy

echo "Starting TI-Rex..."
exec "$@"
