# Copy Fail (CVE-2026-31431) – Simple Detector & Mitigator

This repository provides a single, self‑contained script to **detect likely Copy Fail (CVE‑2026‑31431) exploitation attempts** and **harden a host** until kernel patches can be applied.  
Copy Fail is a Linux kernel local privilege escalation that uses `AF_ALG` + `splice()` to perform a controlled 4‑byte write into the page cache of any readable file, enabling in‑memory modification of setuid binaries (for example `/usr/bin/su`) without touching disk [web:2][web:3][web:5][web:8].

> **Important:** This tool does **not** fix the kernel bug. It helps you:
> - Detect suspicious activity that matches the public exploit chain.
> - Apply temporary hardening measures.
> - Quickly verify whether your host appears vulnerable.

---

## 1. How the original exploit works (high‑level)

Public writeups and PoCs (for example, by Theori/Xint Code and community repos) describe a compact (≈700‑byte) Python exploit that works on most current distributions [web:2][web:5][web:8]. Although implementations differ, they share the same basic steps:

1. **Open an AF_ALG crypto socket**  
   - The exploit uses the Linux userspace crypto API (`AF_ALG`) with an AEAD/`algif_aead` algorithm, typically via Python’s `socket` module [web:2][web:3].  
   - It configures a context that triggers a buggy “in‑place” copy path in the kernel’s `authencesn` crypto template [web:2][web:8].

2. **Abuse `splice()` into the crypto socket**  
   - The exploit opens a **target file** that is readable but often privileged, typically a setuid binary such as `/usr/bin/su` [web:3][web:5].  
   - Using `splice()`, it maps that file into the AF_ALG socket pipeline so the kernel will operate directly on the file’s page cache pages [web:3].  

3. **Trigger a failed crypto operation that corrupts page cache**  
   - By providing invalid or mismatched authentication data, the HMAC check fails as expected, but the kernel leaves a small (4‑byte) overwrite in the page cache [web:3][web:8].  
   - The attacker controls:
     - The **target file** (any readable file, usually a setuid root binary).  
     - The **offset** into the cached pages.  
     - The **4‑byte payload** written [web:3].  

4. **Stage payload into a setuid binary and execute it**  
   - The exploit repeats the primitive across successive offsets to build a small “patch” into the cached image of `/usr/bin/su` or a similar binary [web:3][web:5].  
   - When the attacker later runs `su`, the process executes the modified, in‑memory binary and yields a **root shell**, even though the on‑disk file remains clean [web:2][web:3][web:5].  

5. **Why detection is hard**  
   - Traditional file integrity monitoring tools only look at disk; they see no change, because the exploit modifies the **page cache only** [web:2][web:5][web:8].  
   - Container boundaries are also bypassed, because all containers share the host kernel and its page cache [web:2][web:9][web:12].

Kadir’s IOC toolkit focuses on covering these aspects from a defender’s point of view, with **auditd rules**, **eBPF monitoring of AF_ALG + splice chains**, and **page‑cache vs disk divergence detection for setuid binaries**, plus Sigma rules for SIEMs [web:7]. This project takes the same ideas but compresses them into a single, simpler script.

---

## 2. What this script does

The `copyfail-guard.sh` script provides:

1. **Vulnerability check**
   - Detects whether the running kernel is likely affected (based on version heuristics and presence of vulnerable modules such as `algif_aead` and `authencesn`) [web:2][web:6][web:12].  

2. **Detector**
   - Checks for suspicious patterns in recent logs:
     - `AF_ALG` socket creation by unprivileged users (if auditd rules exist).  
     - Unusual `su` invocations following crypto/audit events.  
   - Optionally verifies **hash drift** of key setuid binaries (e.g. `/usr/bin/su`, `/usr/bin/passwd`) by:
     - Comparing against a baseline file of known good hashes.  
     - Warning if the current hash differs from the stored one (which may indicate a prior compromise, disk tampering, or a missed Copy Fail payload).  

3. **Mitigator / Hardening**
   - Optionally:
     - Restricts use of `AF_ALG` to root using simple sysctl and file permission checks, where viable [web:2][web:6].  
     - Suggests disabling the vulnerable module (`algif_aead`) if it is loadable as a module and you can blacklist it [web:2][web:6][web:12].  
     - Assists with kernel patch validation (shows current kernel and advises on updating).

4. **Reporting**
   - Prints a concise report:
     - Kernel and module status.  
     - Detection findings (suspicious events, hash mismatches).  
     - Recommended next actions.  

This is intentionally minimal: it does not replace a full eBPF + SIEM stack, but gives a single file you can drop onto a host or container for quick triage.

---

## 3. Usage

### 3.1. Download

```bash
curl -O https://raw.githubusercontent.com/Eremiel/CopyFailMitigation/refs/heads/main/copyfail-guard.sh
chmod +x copyfail-guard.sh
```

(Replace with your actual repo URL.)

### 3.2. Run in detection-only mode

```bash
sudo ./copyfail-guard.sh detect
```

This will:

- Check whether the system appears vulnerable.  
- Look for suspicious `AF_ALG` usage and recent `su` executions.  
- Compare setuid binary hashes against a local baseline file (if present).  

### 3.3. Initialize or refresh baseline hashes

```bash
sudo ./copyfail-guard.sh baseline
```

This:

- Computes hashes for common setuid binaries (configurable inside the script).  
- Stores them in `./copyfail-baseline.sha256`.  
- Should be run **once on a known‑good system**, ideally immediately after installing vendor security updates.

### 3.4. Apply hardening (temporary mitigation)

```bash
sudo ./copyfail-guard.sh harden
```

This attempts to:

- Tighten permissions around AF_ALG interfaces where possible.  
- Suggest or assist in blacklisting vulnerable modules (no automatic editing of system files unless you opt in inside the script).  
- Remind you to install vendor kernel patches.

**Note:** Hardening may break workloads that depend on user‑space crypto via `AF_ALG`. Use with care in production.

---

## 4. Output examples

Detection report (example):

```text
[+] Kernel: 5.15.0-101-generic
[!] Kernel version appears in affected range for CVE-2026-31431 (Copy Fail)
[+] Module algif_aead: loaded
[+] Module authencesn: present (built-in or available)
[+] Baseline file: ./copyfail-baseline.sha256
[+] su: hash matches baseline
[+] passwd: hash matches baseline
[+] No suspicious AF_ALG audit events for unprivileged users in last 24h
Status: VULNERABLE KERNEL, NO IOC DETECTED
Recommendation: Apply vendor kernel updates and re-run this tool after reboot.
```

Hardening report (example):

```text
[+] Attempting basic hardening (non-destructive)
[+] Suggested: blacklist algif_aead in /etc/modprobe.d/blacklist-copyfail.conf
[+] Suggested: ensure kernel updates are installed from your distribution
Status: HARDENING SUGGESTED (manual steps required)
```

---

## 5. Limitations and recommendations

- This script does not inspect raw page‑cache state and **cannot reliably prove** that no in‑memory tampering occurred.  
- Logs and audit rules may be incomplete or absent; sophisticated attackers may clear traces.  
- The only definitive mitigation is to **update the kernel to a fixed version** released by your Linux vendor [web:2][web:6][web:12].  
- For high security environments, consider deploying:
  - eBPF monitors that correlate `AF_ALG` + `splice()` usage per PID.  
  - SIEM integration with Copy Fail–specific Sigma rules (as in Kadir’s IOC toolkit) [web:7].  

---

## 6. References

- Xint Code / Theori – Copy Fail technical analysis [web:2][web:8].  
- Vendor and CERT advisories for CVE‑2026‑31431 [web:6][web:11][web:12][web:14].  
- Community IOC toolkit repository description and posts (Kadir’s `copy-fail-CVE-2026-31431-IOC`) [web:7][web:10].  

Use this script and documentation as a starting point and adapt it to your environment’s logging, monitoring, and compliance requirements.
