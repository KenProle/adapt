# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ADAPT (Automated Dynamic Application Penetration Testing) is a Python 3 tool that drives OWASP ZAP, nmap, testssl.sh and wig against a target web application, runs a set of OWASP Testing Guide checks (OTG-*), and writes filtered findings to JSON/XML. It targets Linux (developed on Ubuntu 16.04); macOS install is partial and Windows is unsupported. Clone with `autocrlf` disabled — CRLF line endings break `install.sh`.

## Commands

All commands must be run from the repo root: every module resolves paths via `os.getcwd()` (e.g. `./var/configuration.json`, `./tmp/`, `./output/`, `./lib/testssl.sh/`).

- Install (Linux, run as a normal user, not root — it uses sudo internally): `./install.sh`
  - Installs apt deps, ZAP 2.7.0 to `/opt/ZAP_2.7.0`, wig, and clones testssl.sh into `lib/`, SecLists into `var/`, then touches `var/adapt_installed`. `adapt.py` re-runs the installer automatically if any of those markers are missing.
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

## Gotchas

- `doc/src/` is a duplicate copy of `src/`; the code that runs is `src/`.
- Code uses tabs for indentation.
- `bin/aprint.aprint(msg, c)` is the logging helper (`c`: 0 INFO, 1 WARN, 2 CRIT). It prints nothing unless verbose is on, and in console mode it always labels output INFO, whatever `c` is.
