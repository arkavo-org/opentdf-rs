#!/bin/bash
# Test KAS decryption with real TDF files

set -e

echo "=== OpenTDF-RS KAS Real-World Testing ==="
echo ""

# Check for required environment variables
if [ -z "$KAS_URL" ]; then
    echo "⚠ KAS_URL not set, using default: http://10.0.0.138:8080/kas"
    export KAS_URL="http://10.0.0.138:8080/kas"
fi

if [ -z "$KAS_OAUTH_TOKEN" ]; then
    echo "❌ KAS_OAUTH_TOKEN not set!"
    echo "Please set your OAuth token:"
    echo "  export KAS_OAUTH_TOKEN='your-token-here'"
    exit 1
fi

echo "Configuration:"
echo "  KAS URL: $KAS_URL"
echo "  Token: ${KAS_OAUTH_TOKEN:0:20}... (${#KAS_OAUTH_TOKEN} chars)"
echo ""

# Build the example
echo "Building kas_decrypt example..."
cargo build --example kas_decrypt --features kas --quiet
echo "✓ Build complete"
echo ""

# Test files from OpenTDFKit
TEST_FILES=(
    "/Users/paul/Projects/arkavo/OpenTDFKit/test_swift.tdf"
    "/Users/paul/Projects/arkavo/OpenTDFKit/test_final.tdf"
    "/Users/paul/Projects/arkavo/OpenTDFKit/test_golden.tdf"
    "/Users/paul/Projects/arkavo/OpenTDFKit/test_spec_430.tdf"
)

SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

for tdf_file in "${TEST_FILES[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ ! -f "$tdf_file" ]; then
        echo "⚠ SKIP: $tdf_file (not found)"
        ((SKIP_COUNT++))
        continue
    fi

    echo "Testing: $(basename "$tdf_file")"
    echo ""

    if cargo run --example kas_decrypt --features kas --quiet -- "$tdf_file" 2>&1; then
        ((SUCCESS_COUNT++))
        echo ""
    else
        echo "❌ FAILED: $tdf_file"
        ((FAIL_COUNT++))
        echo ""
    fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "=== Test Summary ==="
echo "  ✓ Passed:  $SUCCESS_COUNT"
echo "  ✗ Failed:  $FAIL_COUNT"
echo "  ⚠ Skipped: $SKIP_COUNT"
echo "  Total:     $((SUCCESS_COUNT + FAIL_COUNT + SKIP_COUNT))"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi