# Installing and running ADAPT

ADAPT targets Linux. It was last tested on Ubuntu 26.04 with Python 3.14 under
WSL2. Other distributions may work but are unsupported; macOS install is partial
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
* shallow-clones testssl.sh into `lib/` and SecLists into `var/`
* creates a Python venv at `./.venv` from `requirements.txt`

Everything in the checkout is owned by your user. Re-running `./install.sh` is safe,
and fixes root-owned files left by older installs. A full install takes about
2 minutes plus the SecLists download.

`./install.sh clean` removes what the installer put in the checkout (not system
packages or `/opt/ZAP_*`) and empties `output/`.

## Running

Run from the repo root:

    python3 adapt.py --target http://localhost

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

  or set `networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`
  (then `wsl --shutdown`). The host must be used in both `target`/`context` in
  `adapt.config` and the login URL in your auth script. `insecure_bank_login.py`
  looks the Windows host up automatically and can be used as an example.

## DVWA

For testing against a known vulnerable webapp, `lib/dvwa/` has scripts to install
and run a docker container with the Damn Vulnerable Web App.

Make sure docker is installed and running, and the user is in the `docker` group.
This is not automated, but the steps will probably look like

    sudo apt-get install docker.io
    sudo gpasswd -a ${USER} docker

Log out and in again to apply the group change. Then:

    cd lib/dvwa
    ./setup-dvwa.sh

It must be run from inside `lib/dvwa` (it calls `python3 ./setup_dvwa.py`). Browse
to `http://localhost` to check the site is up. The default login is
admin/password; if you see 'database not configured', click the setup button
manually. Then target it with ADAPT (using `login_format.py` as the auth module).
