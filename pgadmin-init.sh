#!/bin/sh

# Convert email address to match pgAdmin folder naming (replacing '@' with '_')
USER_EMAIL_DIR=$(echo "$PGADMIN_DEFAULT_EMAIL" | tr '@' '_')
STORAGE_DIR="/var/lib/pgadmin/storage/$USER_EMAIL_DIR"
PGPASSFILE="$STORAGE_DIR/pgpass"

# Create storage directory
echo "Creating storage directory at $STORAGE_DIR"
mkdir -p "$STORAGE_DIR"

# Create the pgpass file
echo "Creating pgpass file at $PGPASSFILE"
echo "${POSTGRES_HOST}:${POSTGRES_PORT}:*:${POSTGRES_USER}:${POSTGRES_PASSWORD}" > "$PGPASSFILE"

# Set correct permissions and ownership for pgadmin (UID 5050)
chmod 600 "$PGPASSFILE"
chown -R 5050:5050 /var/lib/pgadmin/storage

echo "pgpass file created successfully."

SERVERS_JSON_PATH="/pgadmin4/servers.json"
echo "Creating servers.json file in $SERVERS_JSON_PATH"
cat << EOF > $SERVERS_JSON_PATH
{
    "Servers": {
        "1": {
            "Name": "Postgres DB Server",
            "Group": "Servers",
            "Host": "${POSTGRES_HOST}",
            "Port": ${POSTGRES_PORT},
            "MaintenanceDB": "postgres",
            "Username": "${POSTGRES_USER}",
            "PassFile": "${PGPASSFILE}",
            "SSLMode": "prefer"
        }
    }
}
EOF

echo "$SERVERS_JSON_PATH file created successfully."

echo "Starting pgAdmin4..."
exec /entrypoint.sh
echo "pgAdmin4 started."