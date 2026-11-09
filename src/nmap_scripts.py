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

import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from pprint import pprint


def script_outputs(xml_text):
	"""From nmap's XML output (-oX), return one {script id: output} dict per
	port that has script results, in the order nmap lists them. This is the
	part of python-nmap's scan result ADAPT used."""
	root = ET.fromstring(xml_text)
	results = []
	for port in root.iter("port"):
		scripts = {s.get("id"): s.get("output", "") for s in port.findall("script")}
		if scripts:
			results.append(scripts)
	return results


def run_nmap(host, arguments):
	"""Run nmap with XML output on stdout and return that XML. The arguments
	are passed as a list, never through a shell. Like python-nmap, an error is
	raised only when nmap produced no usable XML."""
	if not host or host.startswith("-"):
		raise ValueError("invalid nmap target: %r" % host)
	# stdin=DEVNULL: otherwise nmap reads keypresses from ADAPT's terminal
	proc = subprocess.run(["nmap", "-oX", "-", host] + list(arguments),
		stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	xml_text = proc.stdout.decode("utf-8", "replace")
	try:
		ET.fromstring(xml_text)
	except ET.ParseError:
		raise RuntimeError("nmap failed (exit %d): %s" % (proc.returncode, proc.stderr.decode("utf-8", "replace").strip()))
	return xml_text

def nmap_target(url):
	"""The host and port nmap should scan for a target URL: the bare host name
	(no scheme, port or path, which nmap can't resolve) and the URL's port, or
	the scheme's default port. Raises ValueError for a URL nmap can't use."""
	u = urlparse(url if "://" in url else "http://" + url)
	host = u.hostname   # lower-case, without brackets around an IPv6 address
	if not host or host.startswith("-"):
		raise ValueError("invalid nmap target in %r" % url)
	port = u.port or (443 if u.scheme == "https" else 80)
	return host, port


def target_options(host):
	"""nmap options every scan of the target needs. -Pn: skip host discovery,
	since many hosts (e.g. Windows) drop ping, and nmap would then call the
	host down and scan nothing; ZAP has just reached it, so it is up. -6 for
	an IPv6 address."""
	return ["-Pn"] + (["-6"] if ":" in host else [])

class nmap_scripting():
	def __init__(self, target, ports, scripts_to_run=None):
		self.target, target_port = nmap_target(target)
		if(ports != None):
			# the configured ports plus the target's own port (e.g. 8080)
			port_list = ports.split()
			if(str(target_port) not in port_list):
				port_list.append(str(target_port))
			self.port_values = ["-p"+",".join(port_list)]
		else:
			self.port_values = []   # "all": nmap's default port list
		self.__valid_scripts = []
		if(scripts_to_run is None):
			# for current project goals only one script is run
			# The idea beaing that any future development or tests can 
			# just call an nmap script and use its information 
			self.__valid_scripts = [
				#"ssl-cert", 					# getthe target's ssl certificate 
				#"ssl-ccs-injection",			# determines if vulnerable to ccs injection (CVE-2014-0224)
				#"ssl-cert-intaddr",				# reports any private ipv4 addrs in the ssl certificate 
				#"ssl-dh-params",				# Weak Diffe-Hellman handshake detection
				#"ssl-enum-ciphers",				# Tries multiple ssl/tsl ciphers and ranks available 
				#"ssl-heartbleed",				# detects if app is vuln to heartbleed 
				#"ssl-known-key",				# checks to see if certificate has any known bad keys 
				#"ssl-poodle",					# checks if app is vuln to poodle 
				#"sslv2-drown",					# checks if app supports sslv2 and is vuln to drown
				#"sslv2",						# checks if it supports older and outdated sslv2
				#"http-vuln-cve2006-3392",		# checks for directory information given by Webmin 
				#"http-vuln-cve2009-3960",		# adobe XML external entity injection 
				#"http-vuln-cve2010-0738",		# checks if Jboss target is vuln to jmx console auth bypass
				#"http-vuln-cve2010-2861",		# Directory draversal agains ColdFusion server 
				#"http-vuln-cve2011-3192",		# Detects DoS vuln on Apache systems 
				#"http-vuln-cve2011-3368",		# Checks Reverse Proxy Bypass on Apache
				#"http-vuln-cve2012-1823",		# Checks for PHP-CGI vulns
				#"http-vuln-cve2013-0156",		# Checks for Ruby object injections 
				#"http-vuln-cve2013-6786",		# Redirection and XXS
				#"http-vuln-cve2013-7091",		# Zero data for local file retrieval 
				#"http-vuln-cve2014-2126",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-2127",		# Cisco ASA privilege escalation vuln
				#"http-vuln-cve2014-2128",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-2129",		# Cisco ASA privilege escalation vuln 
				#"http-vuln-cve2014-3704",		# SQL Injecection for Drupal
				#"http-vuln-cve2014-8877",		# Remote code injection for Wordpress 
				#"http-vuln-cve2015-1427",		# Remote code execution via API exploitation 
				#"http-vuln-cve2015-1635",		# Remote code execution on Microsoft systems 
				#"http-vuln-cve2017-1001000",	# Privilege escalation on Wordpress 
				#"http-vuln-cve2017-5638",		# Remote code execution for Apache Struts 
				#"http-vuln-cve2017-5689",		# Pivilege escaltion for Intel Active management 
				#"http-vuln-cve2017-8917",		# SQL injection for Joomla
				#"http-vuln-misfortune-cookie",	# RomPager Cookie vuln 
				#"http-vuln-wnr1000-creds",		# Admin creds steal from WMR 1000 series 
				#"http-adobe-coldfusion-apsa1301", # Auth bypass via adobe coldfusion 
				#"http-affiliate-id", 			# grabs affiliate network information 
				#"http-apache-negotiation",		# enables mod_negociation,allows potential spidering 
				#"http-apache-server-status",	# attempts to retrieve apache server information 
				#"http-aspnet-debug",			# determines if service enabled aspnet debug mode 
				#"http-auth",					# get authentication scheme 
				#"http-auth-finder",				# spiders for getting http based auth 
				#"http-awstatstotals-exec", 		# remote code execution in Awstats total 
				#"http-axis2-dir-traversal",		# directory traversal in for apache axis2 
				#"http-backup-finder",			# spidering attempt to discover duplicates/backup files 
				#"http-brute",					# basic brute force http auth attack 
				#"http-chrono",					# times page's responsivness 
				#"http-cisco-anyconnect",		# connects as cisco AnyClient and retrieves basic information 
				#"http-coldfusion-subzero",		# admin creds steal vial coldfusion vuln 
				#"http-comments-displayer",		# displays comments from pages 
				#"http-config-backup",			# searches for duplicates of system/server setup files 
				#"http-cors",					# tests for cross-origin resource sharing 
				#"http-cross-domain-policy",		# checks cross domain policy to expose overly permissive forms 
				#"http-csrf",					# detects csrf forgeries 
				#"http-default-accounts",		# tests for default accounts that may exist 
				#"http-dlink-backdoor",			# checks for a firmware vuln on some dlink routers 
				#"http-dombased-xss",			# uses the dom to leverage javascript 
				#"http-domino-enum-passwords",	# tries to use the hashed Domino passwords 
				#"http-feed",					# tries to get any rss information that may be present 
				#"http-form-brute",				# brute forces http form based authentication 
				#"http-generator",				# display's contents of generator metatab 
				#"http-headers",					# tries to get a head request for "/" 
				#"http-joomla-brute",			# brute force attack against joomla web CMS installations 
				#"http-malware-host",			# signature search for known compromises 
				#"http-proxy-brute",
				#"http-sql-injection",
				"http-methods"					# gets available methods from service (we only care about this for now)
			]
		else:
			for i in scripts_to_run:
				self.__valid_scripts.append(i)

	def run(self):
		arguments = target_options(self.target) + list(self.port_values)
		for script in self.__valid_scripts:
			arguments += ["--script", script]
		return script_outputs(run_nmap(self.target, arguments))

