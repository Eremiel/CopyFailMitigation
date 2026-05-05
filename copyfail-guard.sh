#!/usr/bin/env bash
#
# copyfail-guard.sh
#
# Simple detector and mitigator for Copy Fail (CVE-2026-31431)
# - Vulnerability check (kernel + modules)
# - IOC checks (logs + setuid binary hashes)
# - Optional basic hardening guidance
#
# Usage:
#   sudo ./copyfail-guard.sh detect
#   sudo ./copyfail-guard.sh baseline
#   sudo ./copyfail-guard.sh harden
#
# This script is intentionally conservative: it does not auto-edit system files
# unless you explicitly accept and customize the relevant parts.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
BASELINE_FILE="./copyfail-baseline.sha256"

# Common setuid binaries to track – adjust for your environment
SUID_TARGETS=(
  "/usr/bin/su"
  "/usr/bin/passwd"
  "/usr/bin/chsh"
  "/usr/bin/sudo"
)

# --------- Helpers ---------

log_info() {
  echo "[+] $*"
}

log_warn() {
  echo "[!] $*" >&2
}

log_err() {
  echo "[-] $*" >&2
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_err "This action must be run as root (sudo)."
    exit 1
  fi
}

# --------- Kernel & module checks ---------

check_kernel_vulnerability() {
  local uname_k
  uname_k="$(uname -r)"

  log_info "Kernel: ${uname_k}"

  # Heuristic: Copy Fail affects kernels built since ~2017 and disclosed 2026.
  # For a simple script, we just warn on a broad range; for production, you
  # should maintain a real allow/deny list based on vendor advisories.
  if [[ "${uname_k}" =~ ^[3-6]\. || "${uname_k}" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    log_warn "Kernel version is in a broad range that includes known affected builds for CVE-2026-31431."
    log_warn "Consult your distribution's advisory to confirm if this specific build is vulnerable."
  else
    log_info "Kernel version does not match the generic affected range, but verify with vendor advisories."
  fi

  # Check for algif_aead and authencesn
  if lsmod 2>/dev/null | grep -q "^algif_aead"; then
    log_info "Module algif_aead: loaded"
  else
    # Could be built-in; check modinfo
    if modinfo algif_aead &>/dev/null; then
      log_warn "Module algif_aead: available but not currently loaded (could be loadable)."
    else
      log_info "Module algif_aead: not found (possibly not built)."
    fi
  fi

  if modinfo authencesn &>/dev/null; then
    log_info "authencesn: present (module or built-in)."
  else
    log_warn "authencesn: not found in modinfo (naming or config may differ on this kernel)."
  fi
}

# --------- Baseline hash functions ---------

create_baseline() {
  require_root

  log_info "Creating baseline hash file: ${BASELINE_FILE}"
  : > "${BASELINE_FILE}"

  for bin in "${SUID_TARGETS[@]}"; do
    if [[ -x "${bin}" ]]; then
      sha256sum "${bin}" >> "${BASELINE_FILE}"
      log_info "Recorded baseline for ${bin}"
    else
      log_warn "Skipping missing or non-executable binary: ${bin}"
    fi
  done

  log_info "Baseline creation complete."
  log_info "Store ${BASELINE_FILE} in a safe place (e.g., configuration management or offline backup)."
}

check_hashes_against_baseline() {
  if [[ ! -f "${BASELINE_FILE}" ]]; then
    log_warn "Baseline file ${BASELINE_FILE} not found; run '${SCRIPT_NAME} baseline' on a known-good system."
    return
  fi

  log_info "Checking current hashes against baseline: ${BASELINE_FILE}"
  local tmp_current
  tmp_current="$(mktemp)"

  for bin in "${SUID_TARGETS[@]}"; do
    if [[ -x "${bin}" ]]; then
      sha256sum "${bin}" >> "${tmp_current}"
    fi
  done

  # Compare ignoring ordering differences
  if diff -u <(sort "${BASELINE_FILE}") <(sort "${tmp_current}") >/dev/null 2>&1; then
    log_info "All tracked setuid binaries match baseline hashes."
  else
    log_warn "Hash differences detected between current binaries and baseline!"
    log_warn "This may indicate disk tampering, a missed Copy Fail payload, or legitimate updates."
    log_warn "Review the diff below:"
    diff -u <(sort "${BASELINE_FILE}") <(sort "${tmp_current}") || true
  fi

  rm -f "${tmp_current}"
}

# --------- Simple IOC checks ---------

check_af_alg_audit_events() {
  # This function assumes auditd is installed and logs are present in /var/log/audit/.
  # It searches for AF_ALG usage by non-root users in the last 24h.
  local audit_dir="/var/log/audit"
  if [[ ! -d "${audit_dir}" ]]; then
    log_warn "Audit logs not found in ${audit_dir}; AF_ALG activity may not be visible."
    return
  fi

  log_info "Scanning audit logs for AF_ALG socket creation by unprivileged users (last 24h heuristic)."

  # Very rough heuristic: look for 'AF_ALG' and uid!=0
  local matches
  matches="$(grep -Ei 'AF_ALG' "${audit_dir}"/audit.log* 2>/dev/null | grep -Ev 'uid=0' || true)"

  if [[ -n "${matches}" ]]; then
    log_warn "Potential AF_ALG usage by non-root users detected in audit logs:"
    echo "${matches}" | head -n 20
    log_warn "(showing first 20 matching lines; review audit logs for full details)"
  else
    log_info "No AF_ALG audit events for unprivileged users found by this simple check."
  fi
}

check_su_usage_logs() {
  # Check for unusual recent su usage in auth logs
  local auth_log=""
  if [[ -f /var/log/auth.log ]]; then
    auth_log="/var/log/auth.log"
  elif [[ -f /var/log/secure ]]; then
    auth_log="/var/log/secure"
  fi

  if [[ -z "${auth_log}" ]]; then
    log_warn "Auth log not found; cannot inspect su usage."
    return
  fi

  log_info "Inspecting recent 'su' invocations in ${auth_log} (last ~200 lines)."
  local su_lines
  su_lines="$(grep -Ei 'su\[[0-9]+\]' "${auth_log}" 2>/dev/null | tail -n 200 || true)"

  if [[ -n "${su_lines}" ]]; then
    echo "${su_lines}"
    log_info "Review the above entries for suspicious access patterns."
  else
    log_info "No recent 'su' usage entries found in the last ~200 log lines."
  fi
}

# --------- Hardening guidance ---------

apply_hardening_guidance() {
  require_root

  log_info "Starting basic, mostly non-destructive hardening guidance."
  log_info "This will NOT automatically edit system configuration files by default."

  # 1. Suggest blacklisting algif_aead if it is a loadable module
  if modinfo algif_aead &>/dev/null; then
    local blacklist_file="/etc/modprobe.d/blacklist-copyfail.conf"
    log_info "Suggestion: blacklist algif_aead to prevent loading of vulnerable crypto interface."
    log_info "You can do this by adding the following line to ${blacklist_file}:"
    echo
    echo "    blacklist algif_aead"
    echo
    log_info "Then run 'update-initramfs -u' or your distro equivalent, and reboot."
  else
    log_info "algif_aead module not found; blacklist step may be unnecessary on this kernel."
  fi

  # 2. Vendor kernel updates
  log_info "Ensure your system is fully updated with vendor security patches for CVE-2026-31431."
  log_info "Examples (adjust to your distribution):"
  echo "  - Debian/Ubuntu: apt update && apt full-upgrade"
  echo "  - RHEL/AlmaLinux/CentOS: dnf update or yum update"
  echo "  - SUSE: zypper patch"
  echo

  # 3. AF_ALG usage policy
  log_info "If you do not rely on AF_ALG user-space crypto, consider restricting its use"
  log_info "through MAC policies (SELinux/AppArmor) or by disabling the interface where possible."

  log_info "Hardening guidance complete. Review the above suggestions before applying them."
}

# --------- Main modes ---------

run_detect() {
  require_root
  echo "==== Copy Fail (CVE-2026-31431) Detection ===="

  check_kernel_vulnerability
  echo

  check_hashes_against_baseline
  echo

  check_af_alg_audit_events
  echo

  check_su_usage_logs
  echo

  log_info "Detection run complete. Review warnings above for potential IOCs and risks."
}

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} <command>

Commands:
  detect    Run vulnerability checks and simple IOC detection.
  baseline  Create or refresh baseline hashes for common setuid binaries.
  harden    Show and assist with basic hardening steps (non-destructive by default).

Examples:
  sudo ./${SCRIPT_NAME} baseline
  sudo ./${SCRIPT_NAME} detect
  sudo ./${SCRIPT_NAME} harden
EOF
}

main() {
  local cmd="${1:-}"

  case "${cmd}" in
    detect)
      run_detect
      ;;
    baseline)
      create_baseline
      ;;
    harden)
      apply_hardening_guidance
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      log_err "Unknown command: ${cmd}"
      usage
      exit 1
      ;;
  esac
}

main "$@"
