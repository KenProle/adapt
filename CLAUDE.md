# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

ADAPT (Automated Dynamic Application Penetration Testing) is a Python 3 tool that drives OWASP ZAP, nmap, testssl.sh and wig against a target web application, runs a set of OWASP Testing Guide checks (OTG-*), and writes filtered findings to JSON/XML. It targets Linux (developed on Ubuntu 16.04, currently tested on Ubuntu 26.04 / Python 3.14 under WSL2; `install.sh` requires Python 3.12+); macOS install is partial and native Windows is unsupported. `.gitattributes` forces LF line endings, which `install.sh` needs.

## Commands

All commands must be run from the repo root: every module resolves paths via `os.getcwd()` (e.g. `./var/configuration.json`, `./tmp/`, `./output/`, `./lib/testssl.sh/`).

- Install (Linux, run as a normal user, not root — it uses sudo internally): `./install.sh`
  - Installs apt deps, Java 17+, ZAP (version set by `ZAP_VERSION` in `install.sh`) to `/opt/ZAP_<version>` with a `/opt/zap` symlink that `zap_general.path` uses, wig, and clones testssl.sh into `lib/`, SecLists into `var/`, then touches `var/adapt_installed`. `adapt.py` re-runs the installer automatically if any of those markers are missing.
- Clean: `./install.sh clean`
- Run: `python3 adapt.py [--target URL] [--output file.json|.xml] [--append file] [--risk low|medium|high|paranoid] [--conf ...] [--detail low|medium|high|full|owasp10] [--verbose]`
- Test an auth module standalone: `python3 login_format.py` (calls `service_auth("admin","password")` and prints the result).
- Vulnerable test target: `lib/dvwa/setup-dvwa.sh` starts a DVWA docker container (default creds admin/password; the user must be in the `docker` group). `login_format.py` is written for DVWA.

Unit tests for small local modules live in `tests/` (standard-library `unittest`): `python3 -m unittest discover tests`. Most behaviour is only checked by a real scan (against DVWA or another target); there is no linter or build step.

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

Every PR gets three reviews before it is merged: a code review (`/code-review high <PR#>`), a security review (`/security-review`) and a sec-context review (`/sec-context:review <PR#>`), each run by a fresh agent (or a new session) rather than the session or agent that wrote the change. `/dev-workflow:review-pr <PR#> high` runs all three in fresh agents and posts their findings on the PR; without the dev-workflow plugin, run the three reviews directly in fresh agents and post the comments yourself. Post the results of each review and re-review as a comment on the PR, one comment per review, even when it finds nothing, so the findings are recorded with the PR and not only in a session; the reviewer or the session that asked for the review may post it. Mark each finding as introduced by the PR or pre-existing. File pre-existing findings as a new issue and link it from the PR, which settles them for this PR. For each introduced finding, either fix it or record in the PR why it is accepted; accepting a finding needs the repo owner's agreement, not just the author's. Re-review after fixing whenever a fix touches one of the security-sensitive areas below. This applies to agent-written and human-written PRs alike, and to doc-only PRs: there the sec-context review can be skipped but a brief `/security-review` still runs (`review-pr` skips both security reviews on a docs-only PR; this repo's stricter rule wins). The rule lives here, so it binds Claude sessions; GitHub branch protection on `master` would be needed to enforce it for merges made in the GitHub UI.

The plugins come from the owner's shared [`kenprole-plugins` marketplace](https://github.com/KenProle/claude-plugins), which `.claude/settings.json` declares and from which it enables `dev-workflow` (`review-pr`), [sec-context](https://github.com/KenProle/sec-context) (`/sec-context:review` and `/sec-context:guide`) and [trim-reaper](https://github.com/KenProle/trim-reaper) (the dependency-reduction passes behind the policy below). To set them up, accept the marketplace and its plugins when Claude Code offers them on opening the repo; that is normally enough, since the settings file already enables all three. If the prompt doesn't appear, run `claude plugin marketplace add KenProle/claude-plugins` first (the marketplace must be added before its plugins can be installed), then `claude plugin install dev-workflow@kenprole-plugins --scope project`, and the same for `sec-context@kenprole-plugins` and `trim-reaper@kenprole-plugins`. Those commands write to the tracked `.claude/settings.json`; don't commit any change they make to it unless the PR is meant to change the plugin setup. A checkout set up before this marketplace was adopted still has the old per-plugin `sec-context` and `trim-reaper` marketplaces registered, which load duplicate copies of the skills: remove them with `claude plugin marketplace remove sec-context` and `claude plugin marketplace remove trim-reaper`. `/sec-context:review` checks the change against the sec-context AI code security anti-patterns in its own reviewer agent, which has no Edit or Write tools (it can still run commands, and only read-only git and `gh` ones are pre-approved), so it counts as a fresh reviewer. The marketplace and the plugins follow their repositories' default branches rather than a pinned commit. The repo owner accepted that for sec-context and trim-reaper on #95, and for the `kenprole-plugins` marketplace and `dev-workflow` on #96, because all of them are the owner's own and contain only Markdown skills, templates and an agent definition (no hooks, MCP servers or scripts). Re-check that before accepting a plugin update that adds any of those, and whenever the marketplace's `.claude-plugin/marketplace.json` adds a plugin or changes where a plugin's source points.

Before writing or changing code in one of the security-sensitive areas listed below (subprocesses and shell commands, file paths, network code, credentials and code loading), load `/sec-context:guide` for the relevant topic.

The repository is public, so PR comments and issues are too. Never put credentials, session cookies, tokens, SSH details or target-specific data from scans in them; describe the finding and point to the code instead. For a security finding that is exploitable and not yet fixed, post only a short summary that can't be used to exploit it, and give the details to the repo owner privately (for example in a GitHub private security advisory); its details aren't posted on the PR until its fix is pushed.

Merge with `gh pr merge <N> --squash`, which is the only merge method enabled on GitHub. Each PR lands on `master` as one commit titled with the PR title and described by the PR body, so keep the title in the form "Short summary (#issue)" and update the description when review fixes change the PR. To bring a PR branch up to date with `master`, merge `master` into the branch instead of rebasing, since force-pushing published branches is avoided.

Treat as security-sensitive and review closely:
- `install.sh` (runs sudo), and the code in `adapt.py` that runs it automatically or re-execs into `./.venv`.
- Anything that runs a subprocess or builds a shell command: the ZAP launch (`shell=True`), nmap, testssl.sh.
- File paths built from config or target input, including the local names of logs downloaded over SSH.
- Network code that talks to the target: the raw-socket CONNECT in `inpval_003`, `requests`/`urllib` calls, wig, and ZAP API calls.
- Credentials and code loading: auth modules, how `zap_interface` imports the module named by `auth_module` in config, `//stdin` prompts, and the SSH/SFTP log retrieval in `adapt.py` (SSH password, host-key policy).

## Third-party dependencies

Where they are declared, and how they are pinned:
- Python packages: `requirements.txt`, exact `==` pins (wig as a `git+https` URL pinned to a commit), installed by `install.sh` into `./.venv`. There is no lockfile; transitive packages are resolved by pip at install time.
- Tools fetched by `install.sh`: `ZAP_VERSION`, `TESTSSL_COMMIT` and `SECLISTS_COMMIT` at the top of the script. apt packages and Java are not pinned.
- Everything is pinned to the versions ADAPT was last tested with (Ubuntu 26.04 / Python 3.14 under WSL2), because upstream changes have broken ADAPT before. Bump deliberately, one dependency at a time unless they must move together, and re-test with a real run against DVWA before merging. Keep compatibility with Python 3.12+.
- Changes to `install.sh` or to how dependencies are fetched are security-sensitive (see the review list above).

Policy for adding, upgrading or removing a dependency:
- Minimize third-party dependencies to reduce ongoing updates and maintenance. Prefer the Python standard library, supported platform APIs, or functionality already in the project when they meet the requirements.
- Add a library only when its benefits justify its ongoing maintenance, security and upgrade costs. For simple, narrowly scoped functionality, consider a small local implementation when it is easier to maintain and verify. For security-sensitive functionality (cryptography, authentication, SSH, TLS, and complex parsing such as HTML/XML), use or keep established libraries or vetted platform APIs rather than hand-rolling replacements. Keep other specialized libraries (e.g. paramiko, the ZAP client) when replacement would add security, correctness or maintenance risk.
- Inspect the resolved transitive dependency tree (e.g. `pip install` into a scratch venv, then `pip list` and `pip show <pkg>`) before adding or upgrading a library. Prefer suitable options with fewer transitive dependencies, avoid large trees for functionality ADAPT barely uses, and explain any substantial increase and its update burden.
- When changing existing dependency usage, identify unused or redundant libraries and unnecessary optional integrations as removal candidates. Remove them only within the authorized task scope and after checking code, dynamic imports (auth modules are loaded by name from config), configuration, `install.sh`, `doc/` and scripts under `lib/`. Preserve behavior and Python 3.12+ compatibility, verify the change, and explain justified retention.
- Before adding or upgrading a library or tool, verify the exact package name, repository and publisher against the project's own documentation or repository, and check its registry entry (PyPI, GitHub releases) live. Do not trust registry metadata alone, and never take package names, versions or commit hashes from model memory. Investigate lookalike names, unexpected ownership or repository moves (testssl.sh has moved before), and unfamiliar new packages before proceeding.
- Use the latest stable, supported release compatible with ADAPT. Scrutinize very recent releases and unexpected maintainer or release changes; absence of an advisory is not evidence that a release is safe. Explain any choice of an older release.
- Check the license of the library and its transitive dependencies against ADAPT's Apache-2.0 license and how ADAPT is distributed. Preserve required notices and flag unclear or incompatible terms for the repo owner before proceeding.
- Assess maintenance through support status, unresolved issues, security responsiveness and compatibility with supported Python versions. Release frequency is only one signal; a mature, stable library may need few releases. Reject archived, deprecated or abandoned projects.
- Check current security advisories from official project sources and advisory databases (e.g. GitHub Advisory Database, OSV, PyPI). Report the sources and date checked, affected versions, and applicability to ADAPT. Avoid versions with known applicable vulnerabilities. If advisory lookup is unavailable, stop and report that before adding or upgrading; do not describe an unchecked version as vulnerability-free.
- Keep updates scoped to the task. Let pip resolve transitive dependencies; avoid unrelated upgrades, forced overrides, or pinning a transitive package in `requirements.txt` just to bypass a constraint. Prefer a compatible parent-library update when a transitive dependency needs remediation.
- Before updating, review release notes, migration guidance and dependency constraints for breaking changes (e.g. ZAP API changes, testssl.sh output format, SecLists file moves). Explain concrete effects on ADAPT and the migration work needed. If an update needs a broader migration or hits a compatibility blocker, stop and report the evidence and options before expanding scope. Do not repeatedly attempt speculative upgrades or fixes; resume only with new evidence or an agreed migration plan.
- If you cannot verify these requirements, stop and report the blocker. Do not add or upgrade the dependency unless the repo owner explicitly accepts the identified risk.

## Gotchas

- Code uses tabs for indentation.
- `bin/aprint.aprint(msg, c)` is the logging helper (`c`: 0 INFO, 1 WARN, 2 CRIT). It prints nothing unless verbose is on, and in console mode it always labels output INFO, whatever `c` is.
