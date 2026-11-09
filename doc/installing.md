# Installing and running ADAPT

ADAPT targets Linux. It was last tested on Ubuntu 26.04 with Python 3.14 under
WSL2, and needs Python 3.12 or newer (the pinned scipy requires it). Other
distributions may work but are unsupported; macOS install is partial
and native Windows is unsupported (use WSL, see below).

If running in a vm, it is recommended that it is at least dual core and has
4 GiB of memory and 10 GiB of space.

Depending on the target application, ADAPT can consume a lot of memory when
forking processes and storing results.

## Install

Clone the repository (its `.gitattributes` keeps LF line endings, which
`install.sh` needs, even where `core.autocrlf` is on), then from the repo root,
as a normal user (it refuses to run as root and uses sudo internally):

    ./install.sh

The installer:
* installs apt packages, and Java 17+ if the installed Java is older (newer ZAP needs it)
* installs ZAP into `/opt/ZAP_<version>` with a `/opt/zap` symlink. The version is
  set once, in `ZAP_VERSION` at the top of `install.sh` (currently 2.17.0)
* shallow-clones testssl.sh into `lib/` and SecLists into `var/`, at the commits
  pinned in `TESTSSL_COMMIT` and `SECLISTS_COMMIT` in `install.sh`
* creates a Python venv at `./.venv` from `requirements.txt`, whose versions are
  pinned to the ones ADAPT was last tested with (it stops early if `python3` is
  older than 3.12, and recreates a `.venv` made by an older Python)

`requirements.txt` pins ADAPT's direct Python dependencies only; the packages
they depend on are resolved by pip at install time and can change between
installs.

When the pins change (for example after `git pull`), re-run `./install.sh`
yourself: `adapt.py` only runs it automatically when the install is missing.
That updates the Python packages (except wig: pip keeps an installed wig after
its commit changes, so run `.venv/bin/pip install --force-reinstall --no-deps`
with its `requirements.txt` line). An existing `lib/testssl.sh` or `var/SecLists`
that isn't at the pinned commit is kept, with a warning.

To update a dependency, change its pin, re-run `./install.sh` (for testssl.sh or
SecLists, delete `lib/testssl.sh` or `var/SecLists` first), and re-test. For
SecLists, check that the file ADAPT reads (`default_password_file` in
`var/configuration.json`, currently
`Passwords/Common-Credentials/darkweb2017_top-100.txt`) still exists at the new
commit.

The installer creates its files as your user. Re-running `./install.sh` is safe,
and hands `output/`, `tmp/`, `lib/testssl.sh`, `var/SecLists` and `var/adapt_installed`
back to you if an older install left them owned by root. A full install takes
about 2 minutes plus the SecLists download.

If you cloned on Windows before `.gitattributes` was added, your checkout may
still have CRLF line endings: re-clone, or run
`git rm --cached -r . && git reset --hard` (this discards uncommitted changes).

`./install.sh clean` removes what the installer put in the checkout (not system
packages or `/opt/ZAP_*`) and empties `output/`.

## Running

First set `target` and `context` in `adapt.config` to your application (for
example both `http://localhost:8080/myapp`). `context` decides what ZAP spiders
and scans, and `--target` on the command line does not change it, so keep the
two in step. Then, from the repo root:

    python3 adapt.py

`adapt.py` re-runs itself under `.venv` automatically, so there is no need to
activate the venv or pip install anything. ADAPT checks at startup that `./output`
is writable. See `command_line_options.md` for the options.

## Configuration

Edit `adapt.config`. See `configuration_file.md` and `authentication.md` (in this
directory) for details. Authentication modules shipped in the repo root:
* `login_format.py`: DVWA (admin/password)
* `insecure_bank_login.py`: Insecure Bank (john/test)

## WSL

* Clone and run from the Linux filesystem (e.g. `~/adapt`), not `/mnt/c/...`,
  which is much slower and doesn't handle Linux file ownership and permissions.
* With WSL's default NAT networking, a target running on Windows is not reachable
  at `localhost` from inside WSL. Either use the Windows host IP:

      ip route | awk '/default/ {print $3}'

  and use that host in both `target`/`context` in `adapt.config` and the login
  URL in your auth script. `insecure_bank_login.py` looks this address up
  automatically (as WSL's default gateway) and can be used as an example.
* Or set `networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`
  (then `wsl --shutdown`) and use `localhost` everywhere instead. In mirrored
  mode the default gateway is your LAN router, not Windows, so the automatic
  lookup in `insecure_bank_login.py` does not work; change its login URL to
  `localhost`. Mirrored mode also makes services in WSL (including DVWA, below)
  reachable from your network.

## DVWA

For testing against a known vulnerable webapp, `lib/dvwa/` has scripts to install
and run a docker container with the Damn Vulnerable Web App.

DVWA is deliberately vulnerable: only run it on a machine and network you trust.
It is published on port 80 on all interfaces.

Make sure docker is installed and running, and the user is in the `docker` group.
Membership of `docker` is equivalent to root access on that machine. This is not
automated, but the steps will probably look like

    sudo apt-get install docker.io
    sudo gpasswd -a ${USER} docker

Log out and in again to apply the group change. Then, from inside `lib/dvwa`
(the script calls `python3 ./setup_dvwa.py`, which needs the packages in ADAPT's
venv):

    cd lib/dvwa
    PATH="$PWD/../../.venv/bin:$PATH" ./setup-dvwa.sh

Browse to `http://localhost` to check the site is up. The default login is
admin/password; if you see 'database not configured', click the setup button
manually. Then set `target` and `context` in `adapt.config` to `http://localhost`
and use `login_format.py` as the auth module.
