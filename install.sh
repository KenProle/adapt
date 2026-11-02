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

if [ "$1" == "clean" ]; then
	# Remove everything this script put inside the checkout (system packages
	# and /opt/ZAP_* are left alone), plus the reports in output/.
	if [ ! -f "$launch_dir/adapt.py" ]
	then
		echo "Refusing to clean: $launch_dir does not look like the ADAPT directory"
		exit 1
	fi
	echo "Cleaning $launch_dir..."
	for path in var/SecLists lib/testssl.sh lib/paramiko .venv var/adapt_installed
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

# Install the Python dependencies (requirements.txt, including wig) into
# ./.venv as the current user. adapt.py re-runs itself with .venv/bin/python.
# A venv avoids PEP 668 "externally-managed-environment" errors on current
# distributions and keeps ADAPT's packages out of the system Python.
function install_python_deps {
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
	do_command sudo apt-get update -y
	do_command sudo apt-get install python3-venv python3-pip -y
	do_command sudo apt-get install default-jre -y
	do_command sudo apt-get install nmap -y
	do_command sudo apt-get install bind9-dnsutils -y
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
	for path in output lib/testssl.sh var/SecLists lib/paramiko var/adapt_installed
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
		do_command git clone --depth 1 https://github.com/drwetter/testssl.sh "$launch_dir"/lib/testssl.sh
	else
		echo "FOUND"
	fi

	echo -n "Checking for SecLists: "
	if [ ! -d "$launch_dir"/var/SecLists ]
	then
		echo "NOT FOUND (downloading, this can take a few minutes)"
		do_command git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$launch_dir"/var/SecLists
	else
		echo "FOUND"
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
