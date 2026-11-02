<p align="center"><img src="images/hero.png" alt="Jacob Parmenter: security tools" width="100%"></p>

Five security tools I designed and built. The source is private, so this page shows what each one does. Every terminal image is output from a real run, trimmed to fit.

| Tool | What it does | Built with | Status |
|---|---|---|---|
| [**LSS**](#lss-linux-security-suite) | Audits and hardens Linux against the CIS Benchmark, with rollback | Python | v1.0.2 |
| [**LSS STIG**](#lss-stig) | Audits and hardens Ubuntu against DISA STIGs and writes STIG Viewer checklists | Python | v1.0.0 |
| [**Wraith**](#wraith) | Detects command-and-control activity from how it disturbs the operating system | Python, NumPy, eBPF | v2.6.0, in active development |
| [**SitRep**](#sitrep) | Reads system logs and explains in plain English what went wrong | Rust | v0.2.1 |
| [**APEX**](#apex) | Raises shell scripts to the standard their job calls for, offline | Python | Working |

---

## LSS (Linux Security Suite)

**Audit a Linux host against the CIS Benchmark, fix what can safely be automated, and undo it if something breaks.**

A single command-line tool with no agent and no cloud service. It covers 206 controls across 11 sections and can fix 166 of them automatically.

The other 40 stay audit-only on purpose. Repartitioning, bootloader edits and account decisions can take a machine down or destroy evidence, so LSS gives the operator the exact steps instead of guessing.

Here's a stock Ubuntu 24.04 machine before hardening, and after hardening and a reboot:

<table>
<tr>
<td width="50%"><img src="images/lss-before.png" alt="LSS audit of a stock Ubuntu 24.04 host: 51 percent hardened, 72 failing controls"></td>
<td width="50%"><img src="images/lss-after.png" alt="LSS audit after hardening and a reboot: 89 percent hardened, 4 failing controls"></td>
</tr>
</table>

Failing controls dropped from 72 to 4, and the result held after the reboot.

**Built to be safe on a live system**

- **Rollback journal:** every change is recorded with a backup of the file and its undo command. Rollback replays them in reverse and reports anything it couldn't undo. In the run above it finished with no errors, even after the reboot, and `sshd_config`, `sysctl.conf`, `fstab` and `login.defs` came back byte-identical. One kernel setting that can't be changed back while running returns to normal at the next boot, and LSS says so.
- **Lockout protection:** LSS checks before making changes that could cut you off. Here it refused to disable root SSH login because the machine had no other admin account:

<p align="center"><img src="images/lss-harden.png" alt="LSS harden output for SSH controls, skipping a fix that would cause a lockout" width="80%"></p>

- **No shell commands:** undo steps never run through a shell, and a regression test enforces that.
- **Honest results:** a check that can't read its evidence reports that, instead of passing.

---

## LSS STIG

**The DISA STIG edition: audit, harden and roll back, with a checklist ready for STIG Viewer 3.**

It covers all 194 rules of the Canonical Ubuntu 24.04 LTS STIG, V1R6, with no third-party dependencies, so it works on air-gapped machines. Every audit writes a `.cklb` checklist with the evidence for each automated check.

Here's a stock Ubuntu 24.04 machine before hardening, and after hardening and a reboot:

<table>
<tr>
<td width="50%"><img src="images/stig-before.png" alt="LSS STIG audit of a stock Ubuntu 24.04 host: 123 open findings"></td>
<td width="50%"><img src="images/stig-after.png" alt="LSS STIG audit after hardening and a reboot: 18 open findings, none auto-fixable"></td>
</tr>
</table>

One run applied 102 fixes with no errors and took open findings from 123 to 18. Those 18 need an operator's decision. After rollback, audit results, packages, services, firewall state and SSH settings all matched the original machine.

**It doesn't blindly apply DISA's fix text.** Some published fixes would damage the machine, so LSS STIG does what the rule's check actually verifies:

| Rule | DISA's fix text | What could go wrong | What LSS STIG does |
|---|---|---|---|
| V-270824 | `chmod -R 755` on command directories | Strips setuid from `sudo`, `su` and `passwd` | Removes only the directory's write bits |
| V-270655 | `ufw enable` | Locks out a remote admin | Sets `ufw limit` on SSH ports first |
| V-270645 | Purge `systemd-timesyncd` | Leaves the machine with no time daemon | Installs chrony first |
| V-270694 | Loop around the consent prompt | Hangs any login shell with no terminal at 100% CPU | Refuses that session |

---

## Wraith

**Detects command-and-control (C2) activity from how it disturbs the operating system, not from what its traffic looks like.**

An implant can encrypt its traffic and disguise its domains, but it can't run without creating threads, allocating memory and opening sockets. Wraith learns what normal looks like across 12 OS signals and flags activity that falls outside it.

Wraith is the reference implementation of my paper: [*The Wraith: Manifold-Based Command-and-Control Detection Through Involuntary Operating System Telemetry with Blind Dual-Layer Validation*](https://doi.org/10.5281/zenodo.19561081).

```mermaid
flowchart LR
    A["Layer 1 (supervised)<br/>signatures, beacon timing,<br/>DNS, JA3/JARM, PCAP"] --> C{"Agreement test<br/>after both finish"}
    B["Layer 2 (unsupervised)<br/>12 OS signals,<br/>Deep SVDD, EVT threshold"] --> C
    C --> D["Cohen's kappa,<br/>permutation test,<br/>mutual information"]
```

The two layers share no data, so their agreement is a real test of whether the unsupervised detector works. It also flagged a C2 framework that Layer 1 was never told about:

<p align="center"><img src="images/wraith-validate.png" alt="Wraith blind validation: kappa 0.992, both hypotheses confirmed" width="80%"></p>

An event-driven eBPF fast path catches short bursts of hands-on-keyboard activity that one-second sampling averages away:

<p align="center"><img src="images/wraith-ttd.png" alt="Wraith time-to-detect benchmark: fast path detects 8 of 8 sessions at a 110 ms median" width="90%"></p>

> **Where it stands:** both results above come from synthetic workloads, so they aren't field detection rates. Validation against real captures and live implants is the next stage of the project.

---

## SitRep

**Tells you what went wrong with a machine, why it matters and what to type next.**

SitRep reads the system logs on Linux or macOS, matches them against about 50 built-in failure patterns, and prints a ranked report. This run used a sample log with disk and memory failures:

<p align="center"><img src="images/sitrep.png" alt="SitRep report explaining a filesystem forced read-only, with likely causes and next steps" width="80%"></p>

- **Fully offline:** no network code at all, and CI fails the build if any is added.
- **One binary:** Linux builds are statically linked and macOS gets a universal binary.
- **Learns new patterns:** lines it doesn't recognize are grouped, and it drafts rules for them.
- **Works with automation:** JSON output and exit codes for cron and CI, plus piped logs from remote servers.

---

## APEX

**Works out what a script is for, then raises it to the standard for that kind of work.**

| If the script is for | APEX raises it to |
|---|---|
| CIS hardening | DISA STIG practices |
| Forensic acquisition | Chain of custody, dual hashing and verification, write-blocking |
| OS installation | Unattended or interactive installs with preflight checks and destroy guards |
| Anything else | Strict mode, error traps, logging, locking and proper command-line options |

The engine is deterministic and fully offline, with no third-party dependencies. It adds only what a script is missing, running it again changes nothing, and it checks the result before writing it. Here it upgrades a sample forensic script (trace shortened):

<p align="center"><img src="images/apex.png" alt="APEX classifying a forensic script and listing the changes it applied" width="90%"></p>

---

## Testing

LSS and LSS STIG also went through full harden, reboot and rollback cycles on an Ubuntu 24.04 arm64 VM. Test suites as last run: LSS, LSS STIG, Wraith and APEX on Ubuntu 24.04 arm64, and SitRep on macOS.

| Tool | Result |
|---|---|
| LSS | 1,709 passed, 1 skipped |
| LSS STIG | 91 tests passed |
| Wraith | 675 passed, 4 skipped |
| SitRep | 79 passed |
| APEX | 101 checks passed |

---

## Contact

For a demo or licensing: **jakep8888@proton.me**

Copyright © 2026 Jacob Douglas Parmenter. All rights reserved. See [LICENSE](LICENSE).
