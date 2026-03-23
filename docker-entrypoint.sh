#!/bin/sh
set -e
if [ "${RUN_MIGRATIONS:-}" = "true" ]; then
  echo "Running Prisma migrations..."
  npx prisma migrate deploy
  echo "Running Seeders..."
  npx prisma db seed
fi
exec "$@"
