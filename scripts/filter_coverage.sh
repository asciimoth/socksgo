#!/bin/bash
# filter_coverage.sh - Filter internal test files from Go coverage reports
#
# Usage: ./scripts/filter_coverage.sh [input_file] [output_file]
#
# If no arguments provided:
#   - Reads from coverage.out
#   - Writes to coverage_filtered.out
#
# This script excludes:
#   - *_internal_test.go files (internal test helpers)
#   - client_testhooks.go (test-only hook code)

set -e

INPUT_FILE="${1:-coverage.out}"
OUTPUT_FILE="${2:-coverage_filtered.out}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

echo "Filtering coverage report..."
echo "  Input:  $INPUT_FILE"
echo "  Output: $OUTPUT_FILE"

# Use temp file to handle case where INPUT_FILE == OUTPUT_FILE
TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

# Filter out internal test files and testhooks
grep -v "client_testhooks.go" "$INPUT_FILE" | \
  grep -v "_internal_test.go" > "$TEMP_FILE"

mv "$TEMP_FILE" "$OUTPUT_FILE"
trap - EXIT

# Report statistics
ORIGINAL_LINES=$(wc -l < "$INPUT_FILE")
FILTERED_LINES=$(wc -l < "$OUTPUT_FILE")
REMOVED_LINES=$((ORIGINAL_LINES - FILTERED_LINES))

echo "  Removed $REMOVED_LINES lines from $ORIGINAL_LINES total"
echo "Done."
