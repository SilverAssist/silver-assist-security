#!/usr/bin/env bash
#
# Run the PHPUnit suite and fail if it did not run to the end.
#
# A test (or the code it calls) that ends the PHP process with exit 0 stops the run early while
# PHPUnit itself reports success. The JUnit log is only written completely when the run reaches the
# end, so this checks it was produced and is well formed. For a full run (no arguments) it also
# compares the total with the tests PHPUnit declares (--list-tests). `--list-tests` does not honor
# `--filter`, so with extra arguments only the completeness of the log is checked.
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
EXPECTED=""

if [ "$#" -eq 0 ]; then
    EXPECTED=$(vendor/bin/phpunit --list-tests 2>/dev/null | grep -c '^ - ' || true)
    if [ "$EXPECTED" -eq 0 ]; then
        echo "ERROR: could not determine the number of declared tests (is the WordPress Test Suite installed?)" >&2
        exit 1
    fi
fi

rm -f "$JUNIT"
vendor/bin/phpunit --testdox "$@"

if [ ! -f "$JUNIT" ]; then
    echo "ERROR: PHPUnit exited without writing $JUNIT; the run stopped early." >&2
    exit 1
fi

# Prints the number of tests, or -1 when the log is missing its closing tags (a cut run).
RAN=$(php -r '$x = @simplexml_load_file($argv[1]); echo $x ? (int) $x->testsuite["tests"] : -1;' "$JUNIT")
if [ "$RAN" -lt 0 ]; then
    echo "ERROR: $JUNIT is incomplete; the run stopped early." >&2
    exit 1
fi

if [ -n "$EXPECTED" ] && [ "$RAN" -ne "$EXPECTED" ]; then
    echo "ERROR: PHPUnit ran $RAN of $EXPECTED declared tests; the run stopped early." >&2
    exit 1
fi

echo "OK: the run completed ($RAN tests)."
