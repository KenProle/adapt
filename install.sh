#!/bin/bash

#
#  Automated Dynamic Application Penetration Testing (ADAPT)
#
#  Copyright (C) 2018 Applied Visions - http://securedecisions.com
#
#  Written by Siege Technologies - http://www.siegetechnologies.com/
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

if [[ $EUID -eq 0 ]]; then
echo "This script should no longer be run as root"
exit 1
fi

# The ADAPT checkout this script lives in, wherever it is run from.
launch_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# To upgrade ZAP, change this version and re-run the installer.
ZAP_VERSION=2.17.0
# testssl.sh and SecLists are pinned to the commits ADAPT was last tested with,
# because upstream changes have broken ADAPT before (a moved SecLists file, a
# new testssl.sh JSON layout). Bump them deliberately and re-test.
TESTSSL_REPO=https://github.com/testssl/testssl.sh
TESTSSL_COMMIT=6f0afecee2193135dfa83408e2486bb1d5586496
SECLISTS_REPO=https://github.com/danielmiessler/SecLists.git
SECLISTS_COMMIT=68bcd12457978649d41ae4f56e3b5d2db2b72560
ZAP_DIR=/opt/ZAP_$ZAP_VERSION
ZAP_URL=https://github.com/zaproxy/zaproxy/releases/download/v$ZAP_VERSION/ZAP_${ZAP_VERSION}_Linux.tar.gz

# Run a command quietly; print DONE, or FAILED plus the command's output and abort.
function do_command {
	echo -n "$*: "
	local output
	if output=$("$@" 2>&1)
	then
		echo "DONE"
	else
		local status=$?
		echo "FAILED (exit $status)"
		echo "$output"
		exit 1
	fi
}

# Shallow-fetch one pinned commit of a repo into a directory. It goes into
# <dir>.partial first and is moved into place only when complete, so an
# interrupted download isn't mistaken for an installed copy next time.
function clone_pinned {
	local repo=$1 dir=$2 commit=$3
	local partial="$dir.partial"
	do_command rm -rf "$partial"
	do_command git init -q "$partial"
	do_command git -C "$partial" fetch -q --depth 1 "$repo" "$commit"
	do_command git -C "$partial" -c advice.detachedHead=false checkout -q FETCH_HEAD
	do_command mv "$partial" "$dir"
}

# An existing copy is kept, but say so if it isn't at the pinned commit (e.g.
# an older unpinned install, or after the pin was bumped). --git-dir stops git
# from walking up into ADAPT's own repository when the copy has no .git.
function check_pinned {
	local dir=$1 commit=$2 head
	head=$(git --git-dir="$dir/.git" rev-parse HEAD 2>/dev/null)
	if [ "$head" != "$commit" ]
	then
		echo "  WARNING: $dir is at ${head:-an unknown commit}, not the pinned $commit."
		echo "  To use the pinned version, delete $dir and re-run ./install.sh."
	fi
}

if [ "$1" == "clean" ]; then
	# Remove everything this script put inside the checkout (system packages
	# and /opt/ZAP_* are left alone), plus the reports in output/.
	if [ ! -f "$launch_dir/adapt.py" ]
	then
		echo "Refusing to clean: $launch_dir does not look like the ADAPT directory"
		exit 1
	fi
	echo "Cleaning $launch_dir..."
	for path in var/SecLists var/SecLists.partial lib/testssl.sh lib/testssl.sh.partial lib/paramiko .venv var/adapt_installed
	do
		if [ -e "$launch_dir/$path" ]
		then
			do_command rm -rf "$launch_dir/$path"
		fi
	done
	if [ -d "$launch_dir/output" ]
	then
		do_command find "$launch_dir/output" -mindepth 1 -delete
	fi
	exit 0
fi

# The pinned packages in requirements.txt (scipy in particular) need this.
MIN_PYTHON=3.12

# Succeed if the given interpreter is at least MIN_PYTHON.
function python_ok {
	"$1" -c "import sys; sys.exit(sys.version_info < tuple(map(int, '$MIN_PYTHON'.split('.'))))" &> /dev/null
}

# Stop early, before downloading anything, if python3 is too old.
function check_python {
	echo -n "Checking for Python $MIN_PYTHON+: "
	if python_ok "$1"
	then
		echo "FOUND ($("$1" -V 2>&1))"
	else
		echo "NOT FOUND ($("$1" -V 2>&1))"
		echo "ADAPT's pinned Python packages need Python $MIN_PYTHON or newer."
		exit 1
	fi
}

# Install the Python dependencies (requirements.txt, including wig) into
# ./.venv as the current user. adapt.py re-runs itself with .venv/bin/python.
# A venv avoids PEP 668 "externally-managed-environment" errors on current
# distributions and keeps ADAPT's packages out of the system Python.
function install_python_deps {
	check_python python3
	# A .venv made by an older Python can't install the pinned packages.
	if [ -x "$launch_dir"/.venv/bin/python ] && ! python_ok "$launch_dir"/.venv/bin/python
	then
		echo "Existing .venv uses Python older than $MIN_PYTHON; recreating it."
		do_command rm -rf "$launch_dir"/.venv
	fi
	echo -n "Creating Python virtual environment (.venv): "
	if [ -x "$launch_dir"/.venv/bin/python ] || python3 -m venv "$launch_dir"/.venv
	then
		echo "DONE"
	else
		echo "FAILED"
		exit 1
	fi
	echo -n "Installing Python packages from requirements.txt: "
	local output
	if output=$("$launch_dir"/.venv/bin/pip install -r "$launch_dir"/requirements.txt 2>&1)
	then
		echo "DONE"
	else
		echo "FAILED"
		echo "$output"
		exit 1
	fi
}

if [ "$(uname)" == "Darwin" ]; then
echo "Installing for MacOSX"
	install_python_deps
elif [ "$(uname -s)" == "Linux" ]; then
	sudo --validate # update sudo permissions, so we don't have to enter a passwd for the rest of the script
	echo "Installing for Linux: "
	echo "Please do not press anything until the script is finished, go take a break"
	# Fail before apt and the large downloads if python3 is too old. (If
	# python3 is missing, apt installs it below and install_python_deps checks.)
	if command -v python3 &> /dev/null
	then
		check_python python3
	fi
	do_command sudo apt-get update -y
	do_command sudo apt-get install python3-venv python3-pip -y
	do_command sudo apt-get install default-jre -y
	do_command sudo apt-get install nmap -y
	# testssl.sh needs dig/host; the package is bind9-dnsutils on current
	# releases and dnsutils on older ones (before Ubuntu 20.10 / Debian 11)
	if apt-cache show bind9-dnsutils &> /dev/null
	then
		do_command sudo apt-get install bind9-dnsutils -y
	else
		do_command sudo apt-get install dnsutils -y
	fi
	do_command sudo apt-get install docker.io -y
	do_command sudo apt-get install git -y
	# ZAP 2.16+ needs Java 17 or newer; default-jre is older on some releases.
	echo -n "Checking for Java 17+: "
	java_major=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)
	if [[ -n "$java_major" && "$java_major" -ge 17 ]]
	then
		echo "FOUND (Java $java_major)"
	else
		echo "NOT FOUND (Java ${java_major:-none})"
		echo -n "Installing openjdk-17-jre: "
		if sudo apt-get install openjdk-17-jre -y &> /dev/null
		then
			echo "DONE"
		else
			echo "FAILED"
			exit 1
		fi
	fi

	# ZAP is installed to /opt/ZAP_<version>, and /opt/zap points at it, so
	# zap_general.path in var/configuration.json never needs to change.
	echo -n "Checking for zap $ZAP_VERSION: "
	if [ ! -d "$ZAP_DIR" ]
	then
		echo "NOT FOUND"
		echo -n "Installing zap $ZAP_VERSION: "
		sudo apt-get install wget -y &> /dev/null
		if sudo wget -q -O /opt/zap.tar.gz "$ZAP_URL" &&
			sudo tar -xf /opt/zap.tar.gz -C /opt &&
			[[ -d "$ZAP_DIR" ]]
		then
			sudo rm -f /opt/zap.tar.gz
			echo "DONE"
		else
			sudo rm -f /opt/zap.tar.gz
			echo "FAILED (could not download or unpack $ZAP_URL)"
			exit 1
		fi
	else
		echo "FOUND"
	fi
	sudo ln -sfn "$ZAP_DIR" /opt/zap
	
	# Everything below lives inside the user's checkout, so it is created as
	# the user, not root; ADAPT runs as the user and must be able to write
	# here. Earlier versions of this script used sudo, so hand any root-owned
	# leftovers back to the user.
	for path in output tmp lib/testssl.sh lib/testssl.sh.partial var/SecLists var/SecLists.partial lib/paramiko var/adapt_installed
	do
		if [ -e "$launch_dir/$path" ] && [ -n "$(find "$launch_dir/$path" ! -user "$(id -u)" -print -quit)" ]
		then
			do_command sudo chown -R "$(id -u):$(id -g)" "$launch_dir/$path"
		fi
	done

	echo -n "Checking testssl: "
	if [ ! -d "$launch_dir"/lib/testssl.sh ]
	then
		echo "NOT FOUND"
		clone_pinned "$TESTSSL_REPO" "$launch_dir"/lib/testssl.sh "$TESTSSL_COMMIT"
	else
		echo "FOUND"
		check_pinned "$launch_dir"/lib/testssl.sh "$TESTSSL_COMMIT"
	fi

	echo -n "Checking for SecLists: "
	if [ ! -d "$launch_dir"/var/SecLists ]
	then
		echo "NOT FOUND (downloading, this can take a few minutes)"
		clone_pinned "$SECLISTS_REPO" "$launch_dir"/var/SecLists "$SECLISTS_COMMIT"
	else
		echo "FOUND"
		check_pinned "$launch_dir"/var/SecLists "$SECLISTS_COMMIT"
	fi

	mkdir -p "$launch_dir"/output

	install_python_deps

	# Now to write out a temp file which will indicate that we ran the install script
	touch "$launch_dir"/var/adapt_installed

	echo "ADAPT install: FINISHED"
else
	echo "Unsupported OS, exiting..."
	exit 1
fi
