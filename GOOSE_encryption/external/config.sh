#!/bin/bash
# This script moves crypto_config.h and os_port_config.h from CycloneCRYPTO into the external/Common directory

SOURCE_DIR="./external/"
DEST_DIR="./external/Common"

# Find crypto_config.h
crypto_config=$(find "$SOURCE_DIR" -type f -name "crypto_config.h" | head -n 1)
if [ -n "$crypto_config" ]; then
    echo "Moving crypto_config.h from $crypto_config to $DEST_DIR"
    mv "$crypto_config" "$DEST_DIR"
else
    echo "crypto_config.h not found in $SOURCE_DIR"
fi

# Find os_port_config.h
os_port_config=$(find "$SOURCE_DIR" -type f -name "os_port_config.h" | head -n 1)
if [ -n "$os_port_config" ]; then
    echo "Moving os_port_config.h from $os_port_config to $DEST_DIR"
    mv "$os_port_config" "$DEST_DIR"
else
    echo "os_port_config.h not found in $SOURCE_DIR"
fi

echo "Done."