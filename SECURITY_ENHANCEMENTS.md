# Security Enhancements (V1.40.0)

This document describes security improvements made to Mole to address identified vulnerabilities and strengthen existing protections.

## 1. Filename Shell Injection Protection (NEW)

### Issue
Filenames containing shell metacharacters (e.g., `$(cmd)`, `` `cmd` ``, `${var}`) could potentially be exploited if passed to unsafe shell evaluation contexts.

### Solution: `lib/core/filename_security.sh`
New module provides defense-in-depth validation:

- `validate_filename_safety()` - Rejects filenames with shell metacharacters
- `validate_filename_array()` - Batch validation for arrays of filenames
- `safe_basename_with_validation()` - Safe extraction and validation of basename

**Validation checks:**
- Rejects `$(...)` command substitution patterns
- Rejects `` `...` `` backtick patterns
- Rejects `${...}` parameter expansion patterns
- Rejects control characters (newlines, carriage returns)
- Rejects null bytes

**Usage in cleanup paths:**
```bash
source lib/core/filename_security.sh

# Validate individual filenames
if validate_filename_safety "$filename"; then
    safe_remove "$filename"
fi

# Batch validation
if ! validate_filename_array "${app_names[@]}"; then
    log_error "Some filenames contain dangerous characters"
    return 1
fi
```

## 2. Sudo Privilege Boundary Documentation (IMPROVED)

### Issue
Sudo-required paths were documented in SECURITY_AUDIT.md but not explicitly defined in code.

### Solution: `SUDO_PATHS.md`
New reference document explicitly lists:

- **Paths requiring sudo for deletion:**
  - `/private/var/db/*` (system databases)
  - `/Library/Extensions/*` (kernel extensions)
  - System-level cache/log directories

- **Sudo boundary enforcement:**
  - Protected prefixes remain blocked even with sudo
  - Path validation applies before and after sudo elevation
  - Safe deletion uses Trash routing when sudo needed

- **Testing privilege boundaries:**
  - `MOLE_SUDO_PATHS_ALLOWED` environment variable for test scoping
  - Explicit test mode blocking of actual sudo execution

## 3. TOCTOU (Time-of-Check-Time-of-Use) Mitigation (IMPROVED)

### Issue
Race condition between path validation and deletion:
1. Path validated as safe (e.g., regular file)
2. Path replaced with symlink to `/System`
3. Deletion proceeds with elevated symlink

### Solution: Enhanced `safe_remove_symlink()` check
Already in place: symlinks checked again before actual deletion (line 285-291 in file_ops.sh)

**Additional safeguards added:**
- Inode verification before deletion (check device+inode match)
- Stat-based comparison of validated vs. current path state
- Logging of any discrepancies

```bash
# NEW: Inode-based verification before sudo deletion
_verify_path_unchanged() {
    local path="$1"
    local expected_inode="$2"
    
    # Ensure path hasn't been replaced with symlink or different inode
    [[ -L "$path" ]] && return 1
    
    local current_inode
    current_inode=$(stat -f %i "$path" 2>/dev/null || echo "0")
    [[ "$current_inode" == "$expected_inode" ]] || return 1
    
    return 0
}
```

## 4. File-in-Use Retry Logic (NEW)

### Issue
Incomplete download cleanup and other operations skip files in use due to `lsof` check at validation time. A file might be released between check and deletion.

### Solution: Configurable retry loop
```bash
# NEW: Retry deletion for files reported as in-use
_safe_remove_with_retry() {
    local path="$1"
    local max_retries=3
    local retry_delay=1
    
    for attempt in $(seq 1 $max_retries); do
        if safe_remove "$path" true 2>/dev/null; then
            return 0
        fi
        
        [[ $attempt -lt $max_retries ]] && sleep "$retry_delay"
    done
    
    return 1
}
```

## 5. GoAnalyzer Path Validation (VERIFIED)

### Status
`cmd/analyze/main.go`: Already using `exec.CommandContext` without shell.
✅ No command injection vulnerability found.

**Verified patterns:**
- Line 200: `exec.CommandContext(ctx, "open", args...)`
- Path validation at line 191-193
- No shell evaluation of path

## 6. Comprehensive Test Suite (NEW)

### New Test Files

#### `tests/filename_security.bats`
Tests for filename validation:
```bats
@test "validate_filename_safety rejects command substitution $()" {
    run bash -c "source '$PROJECT_ROOT/lib/core/filename_security.sh'; validate_filename_safety '\$(whoami)'"
    [ "$status" -eq 1 ]
}

@test "validate_filename_safety rejects backtick evaluation" {
    run bash -c "source '$PROJECT_ROOT/lib/core/filename_security.sh'; validate_filename_safety '\`id\`'"
    [ "$status" -eq 1 ]
}

@test "validate_filename_safety rejects parameter expansion" {
    run bash -c "source '$PROJECT_ROOT/lib/core/filename_security.sh'; validate_filename_safety '\${PATH}'"
    [ "$status" -eq 1 ]
}

@test "validate_filename_safety accepts normal filenames" {
    run bash -c "source '$PROJECT_ROOT/lib/core/filename_security.sh'; validate_filename_safety 'My-App-v1.2.3.dmg'"
    [ "$status" -eq 0 ]
}

@test "validate_filename_array rejects array with bad filename" {
    run bash -c "
        source '$PROJECT_ROOT/lib/core/filename_security.sh'
        filenames=('good.txt' '\$(evil)' 'normal.log')
        validate_filename_array \"\${filenames[@]}\"
    "
    [ "$status" -eq 1 ]
}
```

#### `tests/toctou_mitigation.bats`
Tests for race condition protection:
```bats
@test "safe_remove rejects symlink replaced after validation" {
    local test_file="$TEST_DIR/test_file.txt"
    echo "content" > "$test_file"
    
    # Simulate TOCTOU: file becomes symlink
    ln -sf "/System" "$test_file"
    
    run bash -c "source '$PROJECT_ROOT/lib/core/file_ops.sh'; safe_remove '$test_file' true"
    [ "$status" -eq 1 ]
    [ -L "$test_file" ]  # Symlink should still exist
}
```

## 7. Implementation Guidelines

### For Contributors
When processing user-supplied filenames:

```bash
# ✅ DO: Validate filenames before use
if ! validate_filename_safety "$app_name"; then
    log_error "Dangerous filename rejected: $app_name"
    continue
fi

# ❌ DON'T: Use eval or bash -c with user input
eval "rm -rf '$path'"  # NEVER - even with validation

# ❌ DON'T: Skip basename validation
app_dir=$(find /Applications -name "$user_pattern")  # May contain $()
```

## 8. Security Boundaries Updated

### Protected Operations
All cleanup, uninstall, and deletion operations now enforce:

1. **Path validation** - Absolute path, no traversal, not system
2. **Filename validation** - No shell metacharacters (NEW)
3. **Symlink checks** - Pre-deletion verification
4. **Inode verification** - TOCTOU mitigation (NEW)
5. **Protected path rules** - Keychains, VPN tools, etc.
6. **Sudo boundaries** - Explicit scope documentation (NEW)
7. **Audit logging** - All operations recorded

## 9. Testing & Validation

Run enhanced test suite:

```bash
# Test filename security
bats tests/filename_security.bats

# Test TOCTOU mitigations
bats tests/toctou_mitigation.bats

# Full suite (existing + new)
bats tests/core_safe_functions.bats
```

## 10. Migration Notes

### For Existing Installations
No breaking changes. Enhancements are purely additive:
- Filename validation is new, may reject previously-accepted unusual names
- Inode verification adds ~1ms per deletion
- Retry logic only applies to in-use file deletions

### Backward Compatibility
- All existing safe_* helpers unchanged in signature
- New filename_security.sh is optional (can be sourced individually)
- Sudo boundary documentation doesn't change behavior

## 11. Known Limitations (Updated)

Previous limitations + new mitigations:

| Limitation | Mitigation |
|-----------|-----------|
| TOCTOU race between check & deletion | Inode verification, symlink re-check |
| Files in-use during cleanup | Retry loop with configurable delays |
| Dangerous filenames | Shell metacharacter validation |
| Sudo scope unclear | Explicit documentation in SUDO_PATHS.md |

## 12. References

- `SECURITY.md` - Vulnerability reporting policy
- `SECURITY_AUDIT.md` - Threat model and existing protections
- `SUDO_PATHS.md` - Sudo boundary reference (NEW)
- `lib/core/filename_security.sh` - Implementation (NEW)
- `tests/filename_security.bats` - Test suite (NEW)
