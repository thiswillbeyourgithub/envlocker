# Shell wrapper for envlocker — source this file in your shell rc.
# Built with Claude Code.
#
# Usage: envlocker [--keys PATTERN...] encrypt|decrypt

envlocker() {
    if [ -n "${ENVLOCKER_TMPFILE:-}" ]; then
        echo "Error: ENVLOCKER_TMPFILE is already set — another envlocker may be running." >&2
        return 1
    fi

    local tmpfile
    tmpfile="$(mktemp)" || { echo "Error: failed to create temp file." >&2; return 1; }
    export ENVLOCKER_TMPFILE="$tmpfile"

    # Ensure cleanup on any exit path
    _envlocker_cleanup() {
        rm -f "$tmpfile"
        unset ENVLOCKER_TMPFILE
        unset -f _envlocker_cleanup 2>/dev/null
    }

    uv run "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-${(%):-%x}}")")/envlocker.py" "$@"
    local rc=$?

    if [ $rc -eq 0 ] && [ -s "$tmpfile" ]; then
        . "$tmpfile"
    fi

    _envlocker_cleanup
    return $rc
}
