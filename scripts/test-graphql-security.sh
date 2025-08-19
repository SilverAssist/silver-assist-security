#!/bin/bash

##############################################################################
# Silver Assist Security Essentials - GraphQL Security Validation Tests
#
# Tests the 5 critical GraphQL security scenarios to validate plugin protection:
# 1. Introspection disabled
# 2. Query depth limits
# 3. Alias limitations
# 4. Directive duplication limits
# 5. Field duplication limits
#
# Usage: ./test-graphql-security.sh [--domain URL] [--no-confirm] [--help]
# 
# Configuration:
# Method 1: Use command line parameter (RECOMMENDED):
#   ./scripts/test-graphql-security.sh --domain https://your-site.com/graphql
#
# Method 2: Set GRAPHQL_URL environment variable:
#   export GRAPHQL_URL="https://your-wordpress-site.com/graphql"
#   ./scripts/test-graphql-security.sh
#
# Method 3: Modify GRAPHQL_URL variable in the script directly
#
# Parameters:
#   --domain URL     Specify GraphQL endpoint URL to test
#   --no-confirm     Skip confirmation prompts for default URLs
#   --help, -h       Show detailed help information
#
# Examples:
#   ./scripts/test-graphql-security.sh --domain https://mysite.com/graphql
#   ./scripts/test-graphql-security.sh --domain https://dev.example.com/graphql --no-confirm
#   ./scripts/test-graphql-security.sh --no-confirm  # Uses environment variable or default
#
# @package SilverAssist\Security
# @since 1.1.5
# @author Silver Assist
# @version 1.1.6
##############################################################################

# Configuration
# Set GRAPHQL_URL environment variable or modify the default below
# Example: export GRAPHQL_URL="https://your-site.com/graphql"
GRAPHQL_URL="${GRAPHQL_URL:-https://example.com/graphql}"
TEMP_DIR="/tmp/graphql-tests"
mkdir -p "$TEMP_DIR"

# Command line arguments
NO_CONFIRM=false
DOMAIN_PROVIDED=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          SILVER ASSIST SECURITY - GRAPHQL TESTS             ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}Testing GraphQL endpoint: $GRAPHQL_URL${NC}"
    echo ""
}

print_test() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
}

print_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

# Test 1: Introspection Disabled
test_introspection() {
    print_test "TEST 1: INTROSPECTION PROTECTION"
    
    # Test 1.1: Schema introspection
    echo "Testing schema introspection..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { __schema { types { name } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "error"; then
        print_success "Schema introspection blocked"
    else
        print_fail "Schema introspection not blocked"
    fi
    
    # Test 1.2: Circular introspection
    echo "Testing circular introspection query..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { __type(name: \"User\") { fields { type { fields { type { name } } } } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "error"; then
        print_success "Circular introspection blocked"
    else
        print_fail "Circular introspection not blocked"
    fi
    echo ""
}

# Test 2: Query Depth Limits
test_query_depth() {
    print_test "TEST 2: QUERY DEPTH LIMITS"
    
    # Test 2.1: Normal depth query
    echo "Testing normal depth query..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { posts { nodes { title author { node { name } } } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Normal depth query accepted"
    else
        print_warning "Normal depth query rejected (unexpected)"
    fi
    
    # Test 2.2: Excessive depth query
    echo "Testing excessive depth query..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { posts { nodes { author { node { posts { nodes { author { node { posts { nodes { author { node { posts { nodes { title } } } } } } } } } } } } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "depth.*exceeds"; then
        print_success "Excessive depth query blocked"
    else
        print_fail "Excessive depth query not blocked"
    fi
    echo ""
}

# Test 3: Alias Limits
test_alias_limits() {
    print_test "TEST 3: ALIAS LIMITATIONS"
    
    # Test 3.1: Few aliases
    echo "Testing few aliases..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { p1: post(id: \"1\") { title } p2: post(id: \"2\") { title } p3: post(id: \"3\") { title } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Few aliases accepted"
    else
        print_warning "Few aliases rejected (unexpected)"
    fi
    
    # Test 3.2: Many aliases (generate 30 aliases)
    echo "Testing many aliases..."
    aliases_query="query {"
    for i in {1..30}; do
        aliases_query="$aliases_query p$i: post(id: \"1\") { title }"
    done
    aliases_query="$aliases_query }"
    
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$aliases_query\"}" \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "aliases.*maximum"; then
        print_success "Excessive aliases blocked"
    else
        print_fail "Excessive aliases not blocked"
    fi
    echo ""
}

# Test 4: Directive Limits
test_directive_limits() {
    print_test "TEST 4: DIRECTIVE LIMITATIONS"
    
    # Test 4.1: Normal directives
    echo "Testing normal directives..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { post(id: \"1\") @include(if: true) { title @skip(if: false) } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Normal directives accepted"
    else
        print_warning "Normal directives rejected (unexpected)"
    fi
    
    # Test 4.2: Excessive directives (20+ directives)
    echo "Testing excessive directives..."
    directives_query="query { post(id: \"1\")"
    for i in {1..20}; do
        directives_query="$directives_query @include(if: true)"
    done
    directives_query="$directives_query { title } }"
    
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$directives_query\"}" \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "directives.*maximum"; then
        print_success "Excessive directives blocked"
    else
        print_fail "Excessive directives not blocked"
    fi
    echo ""
}

# Test 5: Field Duplication Limits
test_field_duplication() {
    print_test "TEST 5: FIELD DUPLICATION LIMITS"
    
    # Test 5.1: Few duplicate fields
    echo "Testing few duplicate fields..."
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { post(id: \"1\") { title title id id } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Few duplicate fields accepted"
    else
        print_warning "Few duplicate fields rejected (unexpected)"
    fi
    
    # Test 5.2: Excessive field duplication (50+ fields)
    echo "Testing excessive field duplication..."
    field_query="query { post(id: \"1\") {"
    for i in {1..50}; do
        field_query="$field_query id"
    done
    field_query="$field_query } }"
    
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$field_query\"}" \
        -s -w "HTTPSTATUS:%{http_code}")
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q "duplication.*maximum"; then
        print_success "Excessive field duplication blocked"
    else
        print_fail "Excessive field duplication not blocked"
    fi
    echo ""
}

# Test 6: Query Complexity and Timeout
test_complexity_timeout() {
    print_test "TEST 6: QUERY COMPLEXITY & TIMEOUT"
    
    # Test 6.1: Simple query
    echo "Testing simple query..."
    start_time=$(date +%s.%N)
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { posts(first: 5) { nodes { title } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}")
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Simple query executed in ${duration}s"
    else
        print_warning "Simple query failed (unexpected)"
    fi
    
    # Test 6.2: Complex query that should timeout or be rejected
    echo "Testing complex query for timeout/rejection..."
    start_time=$(date +%s.%N)
    response=$(curl -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        -d '{"query": "query { posts(first: 100) { nodes { title content author { node { posts(first: 100) { nodes { title content } } } } } } }"}' \
        -s -w "HTTPSTATUS:%{http_code}" \
        --max-time 10)
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    
    http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
    
    if [[ "$http_code" != "200" ]] || echo "$response_body" | grep -q -E "(complexity|timeout|exceeded)"; then
        print_success "Complex query blocked/timed out in ${duration}s"
    else
        print_fail "Complex query not properly limited"
    fi
    echo ""
}

# Test 7: Rate Limiting
test_rate_limiting() {
    print_test "TEST 7: RATE LIMITING"
    
    echo "Testing rate limiting (making 35 requests)..."
    blocked_count=0
    success_count=0
    
    for i in {1..35}; do
        response=$(curl -X POST "$GRAPHQL_URL" \
            -H "Content-Type: application/json" \
            -d '{"query": "query { posts(first: 1) { nodes { title } } }"}' \
            -s -w "HTTPSTATUS:%{http_code}" \
            --max-time 5)
        
        http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        response_body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
        
        if [[ "$http_code" == "200" ]] && ! echo "$response_body" | grep -q "rate.*limit"; then
            ((success_count++))
        else
            ((blocked_count++))
        fi
        
        # Small delay to avoid overwhelming
        sleep 1
    done
    
    echo "Successful requests: $success_count"
    echo "Blocked requests: $blocked_count"
    
    if [[ $blocked_count -gt 0 ]]; then
        print_success "Rate limiting is working ($blocked_count requests blocked)"
    else
        print_warning "Rate limiting may not be working (no requests blocked)"
    fi
    echo ""
}

# Main execution
main() {
    print_header
    
    echo "Starting GraphQL security validation tests..."
    echo "This will test the 5 critical security scenarios mentioned in the audit."
    echo ""
    
    test_introspection
    test_query_depth
    test_alias_limits
    test_directive_limits  
    test_field_duplication
    test_complexity_timeout
    test_rate_limiting
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    TESTS COMPLETED                          ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Review the results above to validate that all 5 security${NC}"
    echo -e "${YELLOW}scenarios are properly protected by Silver Assist Security.${NC}"
    echo ""
    echo -e "${GREEN}✅ Expected Results:${NC}"
    echo "   • Introspection queries should be blocked/error"
    echo "   • Deep queries (>8 levels) should be rejected"
    echo "   • Queries with >20 aliases should be blocked"
    echo "   • Queries with >15 directives should be blocked"  
    echo "   • Queries with >10 field duplicates should be blocked"
    echo "   • Complex queries should timeout within 5 seconds"
    echo "   • Rate limiting should block excess requests (>30/min)"
}

# Function to display help
show_help() {
    echo "Silver Assist Security Essentials - GraphQL Security Test Suite"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --domain URL     Specify GraphQL endpoint URL to test"
    echo "  --no-confirm     Skip confirmation prompts for default URLs"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0"
    echo "  $0 --domain https://mysite.com/graphql"
    echo "  $0 --domain https://mysite.com/graphql --no-confirm"
    echo "  $0 --no-confirm"
    echo ""
    echo "CONFIGURATION METHODS (in order of priority):"
    echo "  1. Command line parameter: --domain URL"
    echo "  2. Environment variable: export GRAPHQL_URL=\"https://site.com/graphql\""
    echo "  3. Default fallback: https://example.com/graphql"
    echo ""
    echo "This script tests 7 critical GraphQL security scenarios:"
    echo "  • Introspection protection"
    echo "  • Query depth limitations"
    echo "  • Alias abuse prevention"
    echo "  • Directive limitations"
    echo "  • Field duplication limits"
    echo "  • Query complexity & timeout"
    echo "  • Rate limiting"
    echo ""
    exit 0
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                    GRAPHQL_URL="$2"
                    DOMAIN_PROVIDED=true
                    shift 2
                else
                    echo -e "${RED}❌ ERROR: --domain requires a URL argument${NC}"
                    echo "Example: $0 --domain https://mysite.com/graphql"
                    exit 1
                fi
                ;;
            --no-confirm)
                NO_CONFIRM=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                echo -e "${RED}❌ ERROR: Unknown argument: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Validate GraphQL URL format
validate_url() {
    local url="$1"
    
    # Basic URL validation
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9.-]+[.][a-zA-Z]{2,}(/.*)?$ ]]; then
        echo -e "${RED}❌ ERROR: Invalid URL format: $url${NC}"
        echo "URL should be in format: https://domain.com/graphql"
        exit 1
    fi
    
    # Check if it looks like a GraphQL endpoint
    if [[ ! "$url" =~ graphql ]]; then
        echo -e "${YELLOW}⚠️  WARNING: URL doesn't contain 'graphql' - are you sure this is a GraphQL endpoint?${NC}"
        if [[ "$NO_CONFIRM" == false ]]; then
            read -p "Continue with this URL? [y/N]: " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${RED}Testing cancelled.${NC}"
                exit 1
            fi
        fi
    fi
}

# Parse command line arguments
parse_arguments "$@"

# Validate the GraphQL URL
validate_url "$GRAPHQL_URL"

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ ERROR: curl is required but not installed.${NC}"
    exit 1
fi

# Check if bc is available for time calculations
if ! command -v bc &> /dev/null; then
    echo -e "${YELLOW}⚠️  WARNING: bc not found. Time calculations may not work.${NC}"
fi

# Check if GraphQL URL needs confirmation (only for default URL and not when domain was provided via --domain)
if [[ "$GRAPHQL_URL" == "https://example.com/graphql" && "$DOMAIN_PROVIDED" == false && "$NO_CONFIRM" == false ]]; then
    echo -e "${YELLOW}⚠️  WARNING: Using default GraphQL URL (https://example.com/graphql)${NC}"
    echo -e "${YELLOW}Please use --domain parameter or set GRAPHQL_URL environment variable:${NC}"
    echo -e "${YELLOW}  $0 --domain https://your-site.com/graphql${NC}"
    echo -e "${YELLOW}  export GRAPHQL_URL=\"https://your-site.com/graphql\"${NC}"
    echo ""
    read -p "Continue with default URL? [y/N]: " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Testing cancelled. Please configure GraphQL URL first.${NC}"
        exit 1
    fi
elif [[ "$DOMAIN_PROVIDED" == true ]]; then
    echo -e "${GREEN}✅ Using GraphQL URL from --domain parameter: $GRAPHQL_URL${NC}"
elif [[ -n "$GRAPHQL_URL" && "$GRAPHQL_URL" != "https://example.com/graphql" ]]; then
    echo -e "${GREEN}✅ Using GraphQL URL from environment variable: $GRAPHQL_URL${NC}"
fi

echo ""

# Run main function
main

# Cleanup
rm -rf "$TEMP_DIR"
