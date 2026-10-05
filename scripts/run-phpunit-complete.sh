#!/usr/bin/env bash
#
# Run the full PHPUnit suite and fail if it did not run every declared test.
#
# A test (or the code it calls) that ends the PHP process with exit 0 stops the run early while
# PHPUnit itself reports success. This compares the tests PHPUnit declares (--list-tests) with the
# total written to the JUnit log, which is only produced when the run reaches the end.
#
# Usage: bash scripts/run-phpunit-complete.sh [extra phpunit args]
#
# @package SilverAssist\Security
# @since 1.5.4
# @version 1.5.3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

JUNIT="tests/results/junit.xml"

EXPECTED=$(vendor/bin/phpunit --list-tests 2>/dev/null | grep -c '^ - ' || true)
if [ "$EXPECTED" -eq 0 ]; then
    echo "ERROR: could not determine the number of declared tests (is the WordPress Test Suite installed?)" >&2
    exit 1
fi

rm -f "$JUNIT"
vendor/bin/phpunit --testdox "$@"

if [ ! -f "$JUNIT" ]; then
    echo "ERROR: PHPUnit exited without writing $JUNIT; the run stopped early (expected $EXPECTED tests)." >&2
    exit 1
fi

RAN=$(php -r '$x = @simplexml_load_file($argv[1]); echo $x ? (int) $x->testsuite["tests"] : 0;' "$JUNIT")
if [ "$RAN" -ne "$EXPECTED" ]; then
    echo "ERROR: PHPUnit ran $RAN of $EXPECTED declared tests; the run stopped early." >&2
    exit 1
fi

echo "OK: all $RAN declared tests ran."
