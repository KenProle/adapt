#!/usr/bin/python3

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

import os
import sys
import time

if(sys.version_info[0] < 3):
	print("Please run ADAPT in python 3")
	sys.exit()

if(not os.path.isfile("./var/adapt_installed") or
	not os.path.isdir("./lib/testssl.sh") or
	not os.path.isdir("./var/SecLists") or
	not os.path.isfile("./.venv/bin/python")):
	import subprocess
	print("It seems that you have not run the installer script.")
	print("We will now run that briefly before continuing.")
	subprocess.call(["./install.sh"])

# install.sh puts ADAPT's Python packages in ./.venv; re-run under it if
# we were started with another interpreter (e.g. "python3 adapt.py").
venv_dir = os.path.realpath("./.venv")
venv_python = os.path.join(venv_dir, "bin", "python")
if(os.path.isfile(venv_python) and os.path.realpath(sys.prefix) != venv_dir):
	os.execv(venv_python, [venv_python] + sys.argv)


sys.path.insert(0, os.getcwd()+"/src")
sys.path.insert(0, os.getcwd()+"/var")
sys.path.insert(0, os.getcwd()+"/bin")
sys.path.insert(0, os.getcwd()+"/lib")
sys.path.insert(0, os.getcwd()+"/etc")

import json, argparse, threading, paramiko, adapt_config_parser, base64, hashlib, shlex, traceback
from zap_interface import AdaptZap
from owasp_suite import owasp_suite
from adapt_analysis import adapt_analysis
from aprint import aprint
import getpass

if(not os.path.isfile("./var/adapt_installed") or not os.path.isdir("./lib/testssl.sh")):
	print("It seems like you have not run the installer script")

# This parses the main configuration file and returns its 
# location so we don't have as many hard coded location
main_config_file = adapt_config_parser.parse()
with open(main_config_file) as temp:
	temp_args = json.load(temp)
printer = aprint(temp_args["adapt_general"]["verbose"], "adapt_main")
temp.close()

class PenTester():
	def __init__(self, args):
		self.args = args
		printer.aprint("Test bed setup done")
		self.successful = False

	def run(self):
		return self.start_penetration_testing()
	def start_penetration_testing(self):
		printer.aprint(self.args["adapt_general"]["target_name"])
		if(self.args["adapt_general"]["target_name"] is None):
			# This basically means everything failed
			return {}

		printer.aprint("Initializing zap")
		zapper = AdaptZap(self.args)
		printer.aprint("Zap initialized")
		
		printer.aprint("Checking for authorization availability...")
		if(zapper.auth_success):
			printer.aprint("Authorization is available!")
		else:
			self.args["adapt_general"]["skip_authentication"] = True
			for i in self.args["owasp_general"]["tests_that_require_login"]:
				self.args["owasp_general"]["tests_to_run"][i] = False
		
		# Try to spider
		#try:
		printer.aprint("Zap spider starting...")
		if(self.args["zap_general"]["spider_turned_on"]):
			zapper.spider()
		printer.aprint("DONE")
		#except Exception as e:
		#	printer.aprint("FAILED: "+str(e))

		# Try to pscan
		try:
			printer.aprint("Zap pscan starting... ")
			if(self.args["zap_general"]["pscan_turned_on"]):
				zapper.pscan()
			printer.aprint("DONE")
		except Exception as e:
			printer.aprint("FAILED: "+str(e))

		# Try to ascan
		try:
			printer.aprint("Zap ascan starting...")
			if(self.args["zap_general"]["ascan_turned_on"]):
				zapper.ascan()
			printer.aprint("DONE")
		except Exception as e:
			printer.aprint("FAILED: "+str(e))

		try:
			printer.aprint("Pulling results from zap")
			self.zap_results = zapper.get_results()
		except:
			self.zap_results = {
				"alerts":[],
				"sites":[],
				"urls":[],
				"hosts":[]
			}

		printer.aprint("Initializing owasp suite")
		owasp = owasp_suite(self.args, zapper)
		printer.aprint("Owasp initialized")
		printer.aprint("Running suite")
		self.owasp_results = owasp.run()
		printer.aprint("Done running suite")
		printer.aprint("Done scanning")
		self.successful = True
			

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("--target", type=str, help="Attack target specification")
	parser.add_argument("--verbose", type=bool, nargs='?', help="Turns on verbose")
	parser.add_argument("--output", type=str, help="Output file specification")
	parser.add_argument("--append", type=str, help="Append data to output file.")
	parser.add_argument("--risk", type=str, help="Risk value specification: [low, medium, high, paranoid]")
	parser.add_argument("--conf", type=str, help="Confidence value specification: [low, medium, high, paranoid]")
	parser.add_argument("--detail", type=str, help="Specification for analysis detail: [low, medium, high, full]")

	args = parser.parse_args()
	return args

def __unsupported_value(label, value, correct):
	print("Unsupported "+label+" value: "+value)
	print("Please use any from: "+str(correct))
	sys.exit(1)

def __format_from_filename(filename, supported):
	ext = os.path.splitext(filename)[1].lstrip(".").lower()
	if(ext == ""):
		print("Output file '"+filename+"' has no extension; it selects the output format.")
		print("Please use a file name ending in one of: "+", ".join("."+x for x in supported))
		sys.exit(1)
	if(ext not in supported):
		__unsupported_value("output file format", ext, supported)
	return ext

def _host_key_fingerprint(key):
	# Same form as `ssh-keygen -lf`: SHA256:<unpadded base64>
	return "SHA256:"+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")

class UnknownHostKey(paramiko.SSHException):
	pass

class _RejectUnknownHostKey(paramiko.MissingHostKeyPolicy):
	# Default: refuse a server whose key isn't in known_hosts, before any
	# credentials are sent, and say how to add the key.
	def __init__(self, host, port):
		self.host = host
		self.port = port
	def missing_host_key(self, client, hostname, key):
		raise UnknownHostKey(
			"the SSH host key of {} is not in known_hosts ({} {}). ADAPT won't send the SSH password to an unverified server. "
			"Check the fingerprint with the server's admin, then add the key, e.g. "
			"`ssh-keyscan -p {} {} >> ~/.ssh/known_hosts`, or set accept_unknown_host_key = on in adapt.config.".format(
				hostname, key.get_name(), _host_key_fingerprint(key), shlex.quote(str(self.port)), shlex.quote(self.host)))

class _AcceptUnknownHostKey(paramiko.MissingHostKeyPolicy):
	# Opt-in (accept_unknown_host_key = on): accept an unknown key for this run
	# only, without saving it, and say which key was trusted.
	def missing_host_key(self, client, hostname, key):
		print("ADAPT: WARNING: accepting unverified SSH host key for {}: {} {}".format(
			hostname, key.get_name(), _host_key_fingerprint(key)), file=sys.stderr)

def _local_log_name(log_path):
	# Local file name in ./tmp/ for a downloaded log: the remote file's base name
	name = log_path.split("/")[-1]
	if(name in ("", ".", "..") or "." not in name):
		return None
	return name

def ssh_connect(args, attempts=3):
	# Returns a connected (SSHClient, SFTPClient). The server's host key is
	# checked before any credentials are sent.
	hostname = args["ssh_config"]["hostname"]
	# int: paramiko only looks up a bare "host" known_hosts entry when port == 22
	# as an int; the string "22" makes it look for "[host]:22" instead
	port = int(args["ssh_config"]["port"])
	username = args["ssh_config"]["username"]
	password = args["ssh_config"]["password"]
	known_hosts = args["ssh_config"].get("known_hosts")
	accept_unknown = args["ssh_config"].get("accept_unknown_host_key", False)

	printer.aprint("Connecting...")
	client = paramiko.SSHClient()
	# Host keys from ~/.ssh/known_hosts, plus the configured file. A key that
	# differs from a known one always fails (BadHostKeyException), whatever the policy.
	client.load_system_host_keys()
	if(known_hosts is not None):
		path = os.path.expanduser(known_hosts)
		if(not os.path.isfile(path)):
			raise Exception("SSH known_hosts file not found: "+path)
		client.load_host_keys(path)
	if(accept_unknown):
		client.set_missing_host_key_policy(_AcceptUnknownHostKey())
	else:
		client.set_missing_host_key_policy(_RejectUnknownHostKey(hostname, port))

	ssh_connection_timeout = 30
	exception_reason = None

	# Network errors are retried, with longer banner, auth and general timeouts
	# each time. Host key and password errors are not: retrying can't help.
	for attempt in range(1, attempts+1):
		printer.aprint("Attempt {}/{} ... ".format(attempt, attempts))
		try:
			client.connect(
				hostname=hostname,
				username=username,
				password=password,
				port=port,
				banner_timeout=ssh_connection_timeout,
				auth_timeout=ssh_connection_timeout,
				timeout=ssh_connection_timeout
			)
			ftp_client = client.open_sftp()
			printer.aprint("Connected!")
			return client, ftp_client
		except UnknownHostKey as e:
			client.close()
			raise Exception("Not connecting: "+str(e))
		except paramiko.BadHostKeyException as e:
			# This may be an attack: stop at once
			client.close()
			raise Exception("Not connecting: the SSH host key of {} does NOT match the one in known_hosts (got {}, expected {}). "
				"This could be a machine-in-the-middle attack, or the server's key was changed; check with the server's admin.".format(
				e.hostname, _host_key_fingerprint(e.key), _host_key_fingerprint(e.expected_key)))
		except paramiko.AuthenticationException as e:
			# Retrying a wrong password could lock the account
			client.close()
			raise Exception("SSH login to {} as {} failed: {}".format(hostname, username, e))
		except Exception as e:
			printer.aprint("Attempt {} failed: {}".format(attempt, e))
			client.close()
			exception_reason = e
			if(attempt < attempts):
				time.sleep(30)
				ssh_connection_timeout+=60

	raise Exception("Cannot connect to ssh server: "+str(exception_reason))

def ssh_capture_dmesg_logs(args):
	printer.aprint("Getting ssh logs")
	client, ftp_client = ssh_connect(args)

	printer.aprint("Getting files...")
	fetched = set()
	for i in args["ssh_config"]["log_paths"]:

		log_path = i
		if(log_path == "apache2"):
			log_path = "/var/log/http-error.log"
		elif(log_path == "php"):
			log_path = "/var/log/php-scripts.log"
		filename = _local_log_name(log_path)
		if(filename is None):
			print("ADAPT: SSH log path skipped (it must end in a file name with an extension): "+log_path, file=sys.stderr)
			continue
		if(filename in fetched):
			print("ADAPT: SSH log {} skipped: another log path also ends in {}".format(log_path, filename), file=sys.stderr)
			continue
		fetched.add(filename)

		try:
			ftp_client.get(log_path, "./tmp/"+filename)
		except:
			printer.aprint("SSH ERROR: cannot get file at location: "+log_path, 2)
	printer.aprint("Done")
	
	try:
		printer.aprint("Closing...")
		ftp_client.close()
		client.close()
	except:
		pass

def main():
	printer.aprint("Loading config file")
	with open(main_config_file) as datafile:
		args = json.load(datafile)
	datafile.close()

	supported_file_formats = ["json", "xml", "stdout"]
	supported_risk_conf_values = ["low", "medium", "high", "paranoid"]
	supported_analysis_detail = ["low", "medium", "high", "full", "owasp10"]

	printer.aprint("Checking command line args")
	command_line_args = get_args()
	if(command_line_args.target != None):
		args["adapt_general"]["target_name"] = command_line_args.target
	if(command_line_args.verbose):
		args["adapt_general"]["verbose"] = True
	if(command_line_args.output != None and command_line_args.append != None):
		print("Use either --output or --append, not both.")
		sys.exit(1)
	if(command_line_args.output != None):
		args["adapt_general"]["output_file"] = command_line_args.output
		args["adapt_general"]["output_format"] = __format_from_filename(command_line_args.output, ["json", "xml"])
		# --output replaces the file, even if adapt.config sets append = on
		args["adapt_general"]["append"] = False
	if(command_line_args.append != None):
		args["adapt_general"]["output_file"] = command_line_args.append
		# get_results() can only append to JSON; XML would be overwritten
		args["adapt_general"]["output_format"] = __format_from_filename(command_line_args.append, ["json"])
		args["adapt_general"]["append"] = True

	if(command_line_args.conf != None):
		if(command_line_args.conf not in supported_risk_conf_values):
			__unsupported_value("conf", command_line_args.conf, supported_risk_conf_values)
		args["adapt_general"]["analysis_confidence_sensitivity"] = command_line_args.conf

	if(command_line_args.risk != None):
		if(command_line_args.risk not in supported_risk_conf_values):
			__unsupported_value("risk", command_line_args.risk, supported_risk_conf_values)
		args["adapt_general"]["analysis_risk_sensitivity"] = command_line_args.risk

	if(command_line_args.detail != None):
		if(command_line_args.detail not in supported_analysis_detail):
			__unsupported_value("analysis detail", command_line_args.detail, supported_analysis_detail)
		args["adapt_general"]["analysis_detail"] = command_line_args.detail

	if(len(sys.argv) > 1):
		sys.argv = [sys.argv[0]]

	# Fail now, not after a long scan, if the report can't be written.
	output_dirs = {"./output"}
	if(args["adapt_general"]["output_file"]):
		output_dirs.add(os.path.dirname(args["adapt_general"]["output_file"]) or ".")
	for d in output_dirs:
		try:
			os.makedirs(d, exist_ok=True)
		except OSError as e:
			print("Cannot create output directory "+d+": "+str(e))
			sys.exit(1)
		if(not os.access(d, os.W_OK | os.X_OK)):
			print("Output directory "+d+" is not writable by this user.")
			print("If install.sh created it as root, re-run ./install.sh or run: sudo chown -R $USER: "+os.path.abspath(d))
			sys.exit(1)

	printer.aprint("Final config setup...")

	if(args["zap_general"]["hidden"]):
		args["zap_general"]["opts"].append("-daemon")

	if(not args["adapt_general"]["skip_authentication"]):
		if(args["adapt_general"]["username"] == "//stdin"):
			args["adapt_general"]["username"] = getpass.getpass("Valid service username:")

		if(args["adapt_general"]["password"] == "//stdin"):
			args["adapt_general"]["password"] = getpass.getpass("Valid service password:")

	if(args["ssh_config"]["turned_on"]):
		if(args["ssh_config"]["username"] == "//stdin"):
			args["ssh_config"]["username"] = getpass.getpass("SSH username:")

		if(args["ssh_config"]["password"] == "//stdin"):
			args["ssh_config"]["password"] = getpass.getpass("SSH password:")

	printer.aprint("... Done")

	if(args["ssh_config"]["turned_on"]):
		# Check the SSH connection now (host key, known_hosts file, password)
		# rather than finding a problem after a scan that may take hours
		try:
			client, ftp_client = ssh_connect(args, attempts=1)
			ftp_client.close()
			client.close()
		except Exception as e:
			print("ADAPT: SSH check failed, not starting the scan: "+str(e), file=sys.stderr)
			print("Fix the SSH settings in adapt.config, or set ssh_get_logs = off to scan without server logs.", file=sys.stderr)
			sys.exit(1)

	printer.aprint("Test bed setup starting...")
	pentester = PenTester(args)
	pentester.run()
	printer.aprint("Test bed finished")
	if( pentester.successful ):
		if(args["ssh_config"]["turned_on"]):
			try:
				ssh_capture_dmesg_logs(args)
			except Exception as e:
				# Keep the scan results: write the report without the server logs
				print("ADAPT: server logs not collected over SSH: "+str(e), file=sys.stderr)
				printer.aprint(traceback.format_exc(), 2)
	
		analysis = adapt_analysis( pentester.zap_results, pentester.owasp_results,args=args)
		analysis.get_results()

	for i in os.listdir("./tmp/"):
		os.remove("./tmp/"+i)

	return None

if(__name__ == "__main__"):
	main()

