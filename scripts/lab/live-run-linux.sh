#!/bin/sh
# Builds the uploaded caarea source on a Linux lab host and runs it against the live root
# partition (ext4 read straight from the block device), keeping the extracted tree.
set -e
. "$HOME/.cargo/env"
cd "$HOME"
mkdir -p caarea-src
tar xzf caarea-src.tgz -C caarea-src --strip-components=1
cd caarea-src
cargo build --release 2>&1 | tail -2
DEV=$(findmnt -n -o SOURCE / )
STAMP=$(date -u +%Y%m%dT%H%M%S)
echo "root device: $DEV"
sudo ./target/release/caarea -f "$DEV" -o "$HOME/caarea-live-$STAMP.csv" --stage-dir "$HOME/caarea-stage-$STAMP" --overwrite 2>&1 \
  | tee "$HOME/caarea-live-$STAMP.log" | grep -E 'ext4|LVM|Linux image|time zone|journal|total|⚠|Error' | head -40
echo "csv: $HOME/caarea-live-$STAMP.csv ($(stat -c %s "$HOME/caarea-live-$STAMP.csv") bytes)"
echo "stage: $(find "$HOME/caarea-stage-$STAMP" -type f | wc -l) files"
