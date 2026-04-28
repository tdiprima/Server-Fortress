#!/usr/bin/env bash
#
# lynis-report.sh — Parse Lynis audit results into a clean, readable summary.
#
# Runs a Lynis audit (or reads an existing report), then extracts the
# hardening score, warnings, and suggestions into prioritized output.
#
# Usage:
#   sudo ./lynis-report.sh                  # Run fresh scan + summary
#   sudo ./lynis-report.sh --report-only    # Parse existing report only
#   sudo ./lynis-report.sh --html           # Fresh scan + HTML output
#   sudo ./lynis-report.sh --help           # Show help

LYNIS_REPORT="/var/log/lynis-report.dat"
LYNIS_BIN="lynis"
RUN_SCAN=true
OUTPUT_HTML=false
HTML_FILE=""

# --- Category labels from test ID prefixes ---

declare -A CATEGORIES=(
    ["ACCT"]="Accounting"
    ["AUTH"]="Authentication"
    ["BANN"]="Banners"
    ["BOOT"]="Boot & GRUB"
    ["CONT"]="Containers"
    ["CRYP"]="Cryptography"
    ["CUPS"]="Printing"
    ["DBS"]="Databases"
    ["FILE"]="File Systems"
    ["FIRE"]="Firewalls"
    ["HOME"]="Home Directories"
    ["HTTP"]="Web Servers"
    ["KRNL"]="Kernel"
    ["LOGG"]="Logging"
    ["MALW"]="Malware"
    ["NAME"]="Name Services"
    ["NETW"]="Networking"
    ["PKGS"]="Software Packages"
    ["PRNT"]="Printers"
    ["PROC"]="Processes"
    ["SCHD"]="Scheduling"
    ["SHLL"]="Shells"
    ["SNMP"]="SNMP"
    ["SSH"]="SSH"
    ["STRG"]="Storage"
    ["TIME"]="Time & Sync"
    ["TOOL"]="Security Tooling"
    ["USB"]="USB Devices"
)

# --- Functions ---

show_help() {
    cat <<'HELP'
Usage: sudo ./lynis-report.sh [OPTIONS]

Options:
  --report-only   Skip scan, parse existing /var/log/lynis-report.dat
  --html          Generate HTML report (saved next to this script)
  --help, -h      Show this help

Examples:
  sudo ./lynis-report.sh                  # Full scan + terminal summary
  sudo ./lynis-report.sh --report-only    # Just parse last scan
  sudo ./lynis-report.sh --html           # Full scan + HTML file
  sudo ./lynis-report.sh --report-only --html
HELP
}

check_prerequisites() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: Must run as root (Lynis requires it)." >&2
        exit 1
    fi

    if ! command -v "${LYNIS_BIN}" &>/dev/null; then
        echo "ERROR: Lynis not found. Install it first:" >&2
        echo "  Ubuntu/Debian: apt install lynis" >&2
        echo "  RHEL/Rocky:    yum install lynis" >&2
        exit 2
    fi
}

run_scan() {
    echo "Running Lynis audit... (this takes 1-3 minutes)"
    echo "---"
    ${LYNIS_BIN} audit system --no-colors --quick --quiet 2>/dev/null
    local exit_code=$?

    if [[ ${exit_code} -ne 0 ]]; then
        echo "WARNING: Lynis exited with code ${exit_code}. Results may be partial." >&2
    fi

    if [[ ! -f "${LYNIS_REPORT}" ]]; then
        echo "ERROR: Report not found at ${LYNIS_REPORT}" >&2
        exit 3
    fi
}

get_score() {
    grep "^hardening_index=" "${LYNIS_REPORT}" | cut -d'=' -f2
}

score_grade() {
    local score="$1"
    if [[ ${score} -ge 80 ]]; then
        echo "GOOD"
    elif [[ ${score} -ge 60 ]]; then
        echo "FAIR"
    elif [[ ${score} -ge 40 ]]; then
        echo "WEAK"
    else
        echo "CRITICAL"
    fi
}

score_color() {
    local score="$1"
    if [[ ${score} -ge 80 ]]; then
        echo "32" # green
    elif [[ ${score} -ge 60 ]]; then
        echo "33" # yellow
    elif [[ ${score} -ge 40 ]]; then
        echo "31" # red
    else
        echo "31" # red
    fi
}

get_category_label() {
    local test_id="$1"
    local prefix="${test_id%%-*}"
    local label="${CATEGORIES[${prefix}]}"
    if [[ -n "${label}" ]]; then
        echo "${label}"
    else
        echo "${prefix}"
    fi
}

parse_warnings() {
    grep "^warning\[\]=" "${LYNIS_REPORT}" | while IFS= read -r line; do
        local payload="${line#warning[]=}"
        local test_id description details
        test_id="$(echo "${payload}" | cut -d'|' -f1)"
        description="$(echo "${payload}" | cut -d'|' -f2)"
        details="$(echo "${payload}" | cut -d'|' -f3)"
        local category
        category="$(get_category_label "${test_id}")"

        echo "${category}|${test_id}|${description}|${details}"
    done | sort -t'|' -k1,1
}

parse_suggestions() {
    grep "^suggestion\[\]=" "${LYNIS_REPORT}" | while IFS= read -r line; do
        local payload="${line#suggestion[]=}"
        local test_id description details
        test_id="$(echo "${payload}" | cut -d'|' -f1)"
        description="$(echo "${payload}" | cut -d'|' -f2)"
        details="$(echo "${payload}" | cut -d'|' -f3)"
        local category
        category="$(get_category_label "${test_id}")"

        echo "${category}|${test_id}|${description}|${details}"
    done | sort -t'|' -k1,1
}

# --- Terminal Output ---

print_terminal_report() {
    local score
    score="$(get_score)"
    local grade
    grade="$(score_grade "${score}")"
    local color
    color="$(score_color "${score}")"

    echo ""
    echo "============================================"
    echo "       LYNIS SECURITY AUDIT SUMMARY"
    echo "============================================"
    echo ""
    printf "  Hardening Score:  \033[${color};1m%s / 100  (%s)\033[0m\n" "${score}" "${grade}"
    echo ""

    # Warnings
    local warnings
    warnings="$(parse_warnings)"
    local warning_count
    warning_count="$(echo "${warnings}" | grep -c '.' 2>/dev/null || echo 0)"

    if [[ ${warning_count} -gt 0 ]]; then
        echo "--------------------------------------------"
        printf "  \033[31;1mWARNINGS (%d) — Fix these first\033[0m\n" "${warning_count}"
        echo "--------------------------------------------"
        echo ""

        local current_category=""
        while IFS='|' read -r category test_id description details; do
            if [[ "${category}" != "${current_category}" ]]; then
                current_category="${category}"
                printf "  \033[1m[%s]\033[0m\n" "${category}"
            fi
            printf "    \033[31m!\033[0m %-12s %s\n" "${test_id}" "${description}"
            if [[ -n "${details}" && "${details}" != "-" ]]; then
                printf "                   %s\n" "${details}"
            fi
        done <<< "${warnings}"
        echo ""
    else
        echo "  No warnings. Nice."
        echo ""
    fi

    # Suggestions
    local suggestions
    suggestions="$(parse_suggestions)"
    local suggestion_count
    suggestion_count="$(echo "${suggestions}" | grep -c '.' 2>/dev/null || echo 0)"

    if [[ ${suggestion_count} -gt 0 ]]; then
        echo "--------------------------------------------"
        printf "  \033[33;1mSUGGESTIONS (%d) — Improve these when ready\033[0m\n" "${suggestion_count}"
        echo "--------------------------------------------"
        echo ""

        local current_category=""
        while IFS='|' read -r category test_id description details; do
            if [[ "${category}" != "${current_category}" ]]; then
                current_category="${category}"
                printf "\n  \033[1m[%s]\033[0m\n" "${category}"
            fi
            printf "    - %-12s %s\n" "${test_id}" "${description}"
            if [[ -n "${details}" && "${details}" != "-" ]]; then
                printf "                   %s\n" "${details}"
            fi
        done <<< "${suggestions}"
        echo ""
    fi

    echo "--------------------------------------------"
    echo "  Full report: ${LYNIS_REPORT}"
    echo "  Lynis log:   /var/log/lynis.log"
    echo "============================================"
    echo ""
}

# --- HTML Output ---

html_escape() {
    local text="$1"
    text="${text//&/&amp;}"
    text="${text//</&lt;}"
    text="${text//>/&gt;}"
    text="${text//\"/&quot;}"
    echo "${text}"
}

score_html_color() {
    local score="$1"
    if [[ ${score} -ge 80 ]]; then
        echo "#2d7a2d"
    elif [[ ${score} -ge 60 ]]; then
        echo "#b8860b"
    elif [[ ${score} -ge 40 ]]; then
        echo "#cc3300"
    else
        echo "#990000"
    fi
}

print_html_report() {
    local score
    score="$(get_score)"
    local grade
    grade="$(score_grade "${score}")"
    local color
    color="$(score_html_color "${score}")"
    local scan_date
    scan_date="$(date '+%Y-%m-%d %H:%M:%S')"
    local hostname
    hostname="$(hostname)"

    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    HTML_FILE="${script_dir}/lynis-summary-$(date '+%Y%m%d-%H%M%S').html"

    cat > "${HTML_FILE}" <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Lynis Audit Summary — ${hostname}</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #fafafa; color: #333; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
  .score { font-size: 48px; font-weight: bold; color: ${color}; }
  .grade { font-size: 24px; color: ${color}; }
  .meta { color: #666; margin-bottom: 30px; }
  .section { margin: 30px 0; }
  .section h2 { border-left: 4px solid #cc3300; padding-left: 12px; }
  .section.suggestions h2 { border-left-color: #b8860b; }
  .category { font-weight: bold; margin: 15px 0 5px 0; font-size: 16px; color: #555; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th { text-align: left; background: #eee; padding: 8px; border-bottom: 2px solid #ccc; }
  td { padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  .test-id { font-family: monospace; white-space: nowrap; color: #666; width: 120px; }
  .warning-row td { background: #fff0f0; }
  .details { font-size: 13px; color: #888; margin-top: 3px; }
  .none { color: #2d7a2d; font-style: italic; }
</style>
</head>
<body>
<h1>Lynis Security Audit Summary</h1>
<div class="meta">Host: <strong>${hostname}</strong> &mdash; Scanned: ${scan_date}</div>

<div class="score">${score} / 100</div>
<div class="grade">${grade}</div>
HTMLHEAD

    # Warnings section
    local warnings
    warnings="$(parse_warnings)"
    local warning_count
    warning_count="$(echo "${warnings}" | grep -c '.' 2>/dev/null || echo 0)"

    cat >> "${HTML_FILE}" <<'WARN_HEAD'
<div class="section warnings">
<h2>Warnings &mdash; Fix These First</h2>
WARN_HEAD

    if [[ ${warning_count} -gt 0 ]]; then
        local current_category=""
        echo "<table><tr><th>Test ID</th><th>Issue</th></tr>" >> "${HTML_FILE}"
        while IFS='|' read -r category test_id description details; do
            if [[ "${category}" != "${current_category}" ]]; then
                current_category="${category}"
                local escaped_cat
                escaped_cat="$(html_escape "${category}")"
                echo "<tr><td colspan='2' class='category'>${escaped_cat}</td></tr>" >> "${HTML_FILE}"
            fi
            local escaped_desc escaped_details escaped_id
            escaped_id="$(html_escape "${test_id}")"
            escaped_desc="$(html_escape "${description}")"
            escaped_details="$(html_escape "${details}")"
            echo "<tr class='warning-row'><td class='test-id'>${escaped_id}</td><td>${escaped_desc}" >> "${HTML_FILE}"
            if [[ -n "${details}" && "${details}" != "-" ]]; then
                echo "<div class='details'>${escaped_details}</div>" >> "${HTML_FILE}"
            fi
            echo "</td></tr>" >> "${HTML_FILE}"
        done <<< "${warnings}"
        echo "</table>" >> "${HTML_FILE}"
    else
        echo "<p class='none'>No warnings. Nice.</p>" >> "${HTML_FILE}"
    fi
    echo "</div>" >> "${HTML_FILE}"

    # Suggestions section
    local suggestions
    suggestions="$(parse_suggestions)"
    local suggestion_count
    suggestion_count="$(echo "${suggestions}" | grep -c '.' 2>/dev/null || echo 0)"

    cat >> "${HTML_FILE}" <<'SUG_HEAD'
<div class="section suggestions">
<h2>Suggestions &mdash; Improve When Ready</h2>
SUG_HEAD

    if [[ ${suggestion_count} -gt 0 ]]; then
        local current_category=""
        echo "<table><tr><th>Test ID</th><th>Recommendation</th></tr>" >> "${HTML_FILE}"
        while IFS='|' read -r category test_id description details; do
            if [[ "${category}" != "${current_category}" ]]; then
                current_category="${category}"
                local escaped_cat
                escaped_cat="$(html_escape "${category}")"
                echo "<tr><td colspan='2' class='category'>${escaped_cat}</td></tr>" >> "${HTML_FILE}"
            fi
            local escaped_desc escaped_details escaped_id
            escaped_id="$(html_escape "${test_id}")"
            escaped_desc="$(html_escape "${description}")"
            escaped_details="$(html_escape "${details}")"
            echo "<tr><td class='test-id'>${escaped_id}</td><td>${escaped_desc}" >> "${HTML_FILE}"
            if [[ -n "${details}" && "${details}" != "-" ]]; then
                echo "<div class='details'>${escaped_details}</div>" >> "${HTML_FILE}"
            fi
            echo "</td></tr>" >> "${HTML_FILE}"
        done <<< "${suggestions}"
        echo "</table>" >> "${HTML_FILE}"
    else
        echo "<p class='none'>No suggestions.</p>" >> "${HTML_FILE}"
    fi

    cat >> "${HTML_FILE}" <<HTMLFOOT
</div>
<hr>
<p style="color:#999; font-size:12px;">Generated by lynis-report.sh &mdash; ${scan_date}</p>
</body>
</html>
HTMLFOOT

    echo "HTML report saved: ${HTML_FILE}"
}

# --- Argument Parsing ---

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --report-only)
                RUN_SCAN=false
                shift
                ;;
            --html)
                OUTPUT_HTML=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "ERROR: Unknown option: $1" >&2
                show_help
                exit 1
                ;;
        esac
    done
}

# --- Main ---

main() {
    parse_args "$@"
    check_prerequisites

    if [[ "${RUN_SCAN}" == true ]]; then
        run_scan
    else
        if [[ ! -f "${LYNIS_REPORT}" ]]; then
            echo "ERROR: No existing report at ${LYNIS_REPORT}. Run without --report-only first." >&2
            exit 3
        fi
        echo "Using existing report: ${LYNIS_REPORT}"
    fi

    print_terminal_report

    if [[ "${OUTPUT_HTML}" == true ]]; then
        print_html_report
    fi
}

main "$@"
