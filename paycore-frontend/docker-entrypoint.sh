#!/bin/sh
set -e

# Replace environment variables in JavaScript files
# This allows runtime environment variable configuration
if [ -n "$VITE_API_BASE_URL" ]; then
    echo "Setting VITE_API_BASE_URL to: $VITE_API_BASE_URL"
    find /usr/share/nginx/html -type f -name "*.js" -exec sed -i \
        "s|VITE_API_BASE_URL_PLACEHOLDER|$VITE_API_BASE_URL|g" {} \;
fi

# Execute the main command
exec "$@"
