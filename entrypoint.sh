#!/bin/sh
set -e

# Ensure data and avatars directories have correct permissions
# This is needed because mounted volumes may not preserve the ownership
# set during the Docker build
chown -R appuser:appgroup /app/data /app/avatars 2>/dev/null || true

# Switch to appuser and execute the main application
exec su-exec appuser "$@"
