#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$DIR")"
ENV_FILE="$ROOT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: .env file not found at $ENV_FILE."
    exit 1
fi

echo "Loading environment variables from .env..."
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "Starting ACNS-DSIG Server with Supabase profile..."
cd "$ROOT_DIR"
./mvnw spring-boot:run -pl dsig-server -Dspring-boot.run.profiles=supabase
