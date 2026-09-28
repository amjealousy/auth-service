#!/bin/sh
set -eu

if [ -z "${AUTH_DEMO_USERNAME:-}" ] || [ -z "${AUTH_DEMO_PASSWORD:-}" ]; then
    echo "Auth demo user is disabled"
    return 0 2>/dev/null || exit 0
fi

psql --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set=demo_username="$AUTH_DEMO_USERNAME" \
    --set=demo_password="$AUTH_DEMO_PASSWORD" <<-'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO UserAuth (userqn, hpassword)
VALUES (:'demo_username', crypt(:'demo_password', gen_salt('bf', 12)))
ON CONFLICT (userqn) DO UPDATE
SET hpassword = EXCLUDED.hpassword;
SQL
