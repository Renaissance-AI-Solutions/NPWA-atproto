#!/bin/sh

# Startup script for NPWA-atproto services
# Ensures services start properly with database connectivity

set -e

echo "=== NPWA-atproto Startup Script ==="

# PostgreSQL client tools should be available in Docker image
if ! command -v pg_isready > /dev/null 2>&1; then
    echo "Warning: PostgreSQL client tools not available!"
    echo "Proceeding without database health checks..."
fi

# Function to wait for PostgreSQL to be ready
wait_for_postgres() {
    echo "Waiting for PostgreSQL to be ready..."
    if command -v pg_isready > /dev/null 2>&1; then
        while ! pg_isready -h postgres -p 5432 -U postgres > /dev/null 2>&1; do
            sleep 1
        done
        echo "PostgreSQL is ready!"
    else
        echo "PostgreSQL client not available, waiting 10 seconds..."
        sleep 10
        echo "Proceeding without health check..."
    fi
}

# Note: PDS runs migrations automatically when it starts
# No separate migration command is needed for PDS

# Function to run Bsky migrations (if needed)
run_bsky_migrations() {
    echo "Checking if Bsky migrations are needed..."
    cd /app/packages/bsky

    # Check if the migration binary exists
    if [ -f "dist/bin.js" ]; then
        echo "Running Bsky migrations..."
        if node --enable-source-maps dist/bin.js db migrate; then
            echo "Bsky migrations completed successfully"
        else
            echo "Bsky migrations failed, but continuing (migrations might be automatic)"
            echo "Service will attempt to start normally..."
        fi
    else
        echo "Bsky migration binary not found, skipping manual migrations"
        echo "Migrations may run automatically when service starts"
    fi
}

# Function to start PDS service
start_pds() {
    echo "Starting PDS service..."
    echo "Note: PDS will run migrations automatically during startup"
    cd /app/services/pds
    node --heapsnapshot-signal=SIGUSR2 --enable-source-maps --require=./tracer.js index.js
}

# Function to start Bsky service
start_bsky() {
    echo "Starting Bsky service..."
    cd /app/services/bsky
    node --enable-source-maps api.js
}

# Determine which service to start based on the first argument
SERVICE=${1:-pds}

echo "Starting service: $SERVICE"

case $SERVICE in
    pds)
        wait_for_postgres
        # PDS runs migrations automatically, no separate migration step needed
        start_pds
        ;;
    bsky)
        wait_for_postgres
        # Wait a bit more for PDS to be ready
        sleep 5
        # Try to run migrations if available, but don't fail if they don't work
        run_bsky_migrations
        start_bsky
        ;;
    *)
        echo "Unknown service: $SERVICE"
        echo "Usage: $0 [pds|bsky]"
        exit 1
        ;;
esac