#!/bin/bash
# Mole - Filename Security Validation
# Protection against shell injection via malicious filenames

set -euo pipefail

# Prevent multiple sourcing
if [[ -n "${MOLE_FILENAME_SECURITY_LOADED:-}" ]]; then
    return 0
fi
readonly MOLE_FILENAME_SECURITY_LOADED=1

# ============================================================================
# Filename Safety Checks
# ============================================================================

# Reject filenames containing shell metacharacters that could enable injection
# This adds defense-in-depth beyond path validation
validate_filename_safety() {
    local filename="$1"
    
    if [[ -z "$filename" ]]; then
        return 1
    fi
    
    # Reject filenames with shell command substitution patterns
    # - $(...) command substitution
    # - `...` backtick command substitution
    # - $(...) parameter expansion
    # These would only be dangerous if passed unsanitized to eval/bash -c,
    # but we reject them for defense-in-depth
    if [[ "$filename" =~ \$\( ]] || [[ "$filename" =~ \`  ]] || [[ "$filename" =~ \$\{ ]]; then
        return 1
    fi
    
    # Reject newlines (could break log parsing or enable injection)
    if [[ "$filename" =~ $'\n' ]] || [[ "$filename" =~ $'\r' ]]; then
        return 1
    fi
    
    # Reject null bytes (filesystem boundary violation)
    if [[ "$filename" == *$'\0'* ]]; then
        return 1
    fi
    
    return 0
}

# Sanitize array of filenames for safe shell consumption
# Returns exit code 1 if any filename fails validation
validate_filename_array() {
    local -a filenames=("$@")
    
    for filename in "${filenames[@]}"; do
        if ! validate_filename_safety "$filename"; then
            return 1
        fi
    done
    
    return 0
}

# Extract basename safely and validate it
# This is useful when processing user-supplied paths
safe_basename_with_validation() {
    local path="$1"
    
    if [[ -z "$path" ]]; then
        return 1
    fi
    
    local base
    base=$(basename "$path") || return 1
    
    if validate_filename_safety "$base"; then
        echo "$base"
        return 0
    fi
    
    return 1
}
