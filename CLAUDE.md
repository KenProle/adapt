# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ADAPT (Automated Dynamic Application Penetration Testing) is a Python 3 tool that drives OWASP ZAP, nmap, testssl.sh and wig against a target web application, runs a set of OWASP Testing Guide checks (OTG-*), and writes filtered findings to JSON/XML. It targets Linux (developed on Ubuntu 16.04, currently tested on Ubuntu 26.04 / Python 3.14 under WSL2; the pinned requirements need Python 3.12+); macOS install is partial and native Windows is unsupported. `.gitattributes` forces LF line endings, which `install.sh` needs.

## Commands

All commands must be run from the repo root: every module resolves paths via `os.getcwd()` (e.g. `./var/configuration.json`, `./tmp/`, `./output/`, `./lib/testssl.sh/`).

- Install (Linux, run as a normal user, not root — it uses sudo internally): `./install.sh`
  - Installs apt deps, Java 17+, ZAP (version set by `ZAP_VERSION` in `install.sh`) to `/opt/ZAP_<version>` with a `/opt/zap` symlink that `zap_general.path` uses, wig, and clones testssl.sh into `lib/`, SecLists into `var/`, then touches `var/adapt_installed`. `adapt.py` re-runs the installer automatically if any of those markers are missing.
- Clean: `./install.sh clean`
- Run: `python3 adapt.py [--target URL] [--output file.json|.xml] [--append file] [--risk low|medium|high|paranoid] [--conf ...] [--detail low|medium|high|full|owasp10] [--verbose]`
- Test an auth module standalone: `python3 login_format.py` (calls `service_auth("admin","password")` and prints the result).
- Vulnerable test target: `lib/dvwa/setup-dvwa.sh` starts a DVWA docker container (default creds admin/password; the user must be in the `docker` group). `login_format.py` is written for DVWA.

There is no test suite, linter or build step.

## Configuration flow

Two config files, and the relationship matters:

1. `adapt.config` (INI) is the user-facing config.
2. `bin/adapt_config_parser.parse()` reads it, merges it into `var/configuration.json`, **rewrites `var/configuration.json` in place** (also patching ZAP `-dir`/`dirs=` opts to the current path and choosing a random free ZAP port), and returns that path. Expect `var/configuration.json` to show diffs after every run; don't hand-edit values that `adapt.config` controls.
3. `adapt.py` loads the JSON into a nested `args` dict (`adapt_general`, `zap_general`, `owasp_general`, `ssh_config`), then applies CLI overrides. This dict is passed to every component.

Credentials set to `//stdin` are prompted with `getpass` at runtime.

## Architecture / pipeline

`adapt.py` puts `src/`, `bin/`, `lib/`, `var/` on `sys.path`, so modules import each other by bare name (`from aprint import aprint`, `from httpparser.httprequest import HTTPRequest`).

1. **`src/zap_interface.AdaptZap`** launches ZAP as a subprocess (`zap_general.path` + opts, then waits a fixed 60s), connects via `zapv2`, creates a context from `context_name` minus `excluded` paths, then imports the auth module and tries to log in. If auth fails, every test in `owasp_general.tests_that_require_login` is disabled.
2. Spider → passive scan → active scan through ZAP (each toggleable), then ZAP alerts are collected.
3. **`src/owasp_suite.owasp_suite.run()`** runs nmap scripts (`src/nmap_scripts.py`), then calls each test method by name from the hard-coded `test_methods` list, skipping those set off in `tests_to_run`. Each test returns a dict (or list of dicts) built with `create_report(...)`. Several tests are intentional no-ops because ZAP covers them (`authz_001`, `inpval_001/002`, `err_001`, `crypst_002` is produced inside `crypst_001`). `err_002` delegates to `src/error.py`; `sess_001` uses `src/entropy.py`.
4. If SSH is on, `adapt.py` pulls remote log files over SFTP into `./tmp/`.
5. **`src/adapt_analysis.adapt_analysis`** merges ZAP alerts and OWASP reports, filters by risk/confidence sensitivity, shapes them by `analysis_detail` (`owasp10` groups by `var/owasp2017.json` via CWE/`owasp_association`), and writes to `./output/` (timestamped name if no output file).
6. `./tmp/` is wiped at the end of the run.

### Adding an OWASP test

A new test needs all of: a method on `owasp_suite` named after the test id, an entry in its `test_methods` list, a key in `[OWASP_OPTIONS]` of `adapt.config`, and a `tests_to_run` key in `var/configuration.json` (analysis looks up `tests_to_run[report["name"]]`, so the report `name` must equal the test id). Add it to `tests_that_require_login` if it uses the auth module.

### Auth modules

`[AUTH_OPTIONS] auth_module` names a `.py` file importable from the repo root that defines `service_auth(username, password)` returning a dict with `responseHeader`, `responseBody`, `requestHeader`, `requestBody` (str), `cookies` (dict), `rtt` (float) and `successful` (bool). All login-based tests (`AdaptZap.test_login` / `get_session`) go through this function. See `login_format.py` and `doc/authentication.md`.

## Before merging a pull request

Every PR gets an independent code review (`/code-review high <PR#>`) and a security review (`/security-review`) before it is merged, run by a fresh reviewer (a new session or agent) rather than the session or agent that wrote the change. For each finding, either fix it or record in the PR why it is accepted; accepting a finding needs the repo owner's agreement, not just the author's. Re-review after fixing whenever a fix touches one of the security-sensitive areas below. This applies to agent-written and human-written PRs alike, and to doc-only PRs (the security review can be brief there). The rule lives here, so it binds Claude sessions; GitHub branch protection on `master` would be needed to enforce it for merges made in the GitHub UI.

Merge with `gh pr merge <N> --squash`, which is the only merge method enabled on GitHub. Each PR lands on `master` as one commit titled with the PR title and described by the PR body, so keep the title in the form "Short summary (#issue)" and update the description when review fixes change the PR. To bring a PR branch up to date with `master`, merge `master` into the branch instead of rebasing, since force-pushing published branches is avoided.

Treat as security-sensitive and review closely:
- `install.sh` (runs sudo), and the code in `adapt.py` that runs it automatically or re-execs into `./.venv`.
- Anything that runs a subprocess or builds a shell command: the ZAP launch (`shell=True`), nmap, testssl.sh.
- File paths built from config or target input, including the local names of logs downloaded over SSH.
- Network code that talks to the target: the raw-socket CONNECT in `inpval_003`, `requests`/`urllib` calls, wig, and ZAP API calls.
- Credentials and code loading: auth modules, how `zap_interface` imports the module named by `auth_module` in config, `//stdin` prompts, and the SSH/SFTP log retrieval in `adapt.py` (SSH password, host-key policy).

## Gotchas

- Code uses tabs for indentation.
- `bin/aprint.aprint(msg, c)` is the logging helper (`c`: 0 INFO, 1 WARN, 2 CRIT). It prints nothing unless verbose is on, and in console mode it always labels output INFO, whatever `c` is.
