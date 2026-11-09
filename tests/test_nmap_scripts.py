#
#  Automated Dynamic Application Penetration Testing (ADAPT)
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

# Run from the repo root: python3 -m unittest discover tests

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import nmap_scripts
from nmap_scripts import nmap_scripting, nmap_target, run_nmap, script_outputs

# Trimmed from real `nmap -oX -` output.
XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - 192.0.2.1 -Pn -p80,443,8080 --script http-title --script http-methods">
<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>
<script id="http-methods" output="&#xa;  Supported Methods: GET HEAD POST OPTIONS TRACE&#xa;  Potentially risky methods: TRACE"/>
<script id="http-title" output="Welcome &amp; hello"/>
</port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><script id="http-title" output="Login"/></port>
</ports>
<hostscript><script id="nbstat" output="NetBIOS name: X"/></hostscript>
</host>
<runstats><finished time="0"/></runstats>
</nmaprun>"""


class ScriptOutputsTest(unittest.TestCase):
	def test_one_dict_per_port_with_scripts(self):
		self.assertEqual(script_outputs(XML), [
			{"http-methods": "\n  Supported Methods: GET HEAD POST OPTIONS TRACE\n  Potentially risky methods: TRACE",
			 "http-title": "Welcome & hello"},
			{"http-title": "Login"},
		])

	def test_no_hosts(self):
		self.assertEqual(script_outputs('<?xml version="1.0"?><nmaprun><runstats/></nmaprun>'), [])


class RunNmapTest(unittest.TestCase):
	def fake(self, stdout, returncode=0, stderr=b""):
		return mock.Mock(stdout=stdout, stderr=stderr, returncode=returncode)

	def test_argument_list_without_shell(self):
		with mock.patch.object(nmap_scripts.subprocess, "run", return_value=self.fake(XML.encode())) as run:
			self.assertEqual(run_nmap("example.test", ["-p80", "--script", "http-methods"]), XML)
		args, kwargs = run.call_args
		self.assertEqual(args[0], ["nmap", "-oX", "-", "example.test", "-p80", "--script", "http-methods"])
		self.assertFalse(kwargs.get("shell", False))
		self.assertIs(kwargs.get("stdin"), nmap_scripts.subprocess.DEVNULL)

	def test_rejects_option_like_target(self):
		for host in ("", "-iL/etc/passwd", "--script=x"):
			with self.subTest(host=host), self.assertRaises(ValueError):
				run_nmap(host, [])

	def test_no_xml_raises(self):
		with mock.patch.object(nmap_scripts.subprocess, "run", return_value=self.fake(b"", 1, b"nmap: something failed")):
			with self.assertRaisesRegex(RuntimeError, "something failed"):
				run_nmap("example.test", [])

	def test_warnings_with_xml_are_not_errors(self):
		with mock.patch.object(nmap_scripts.subprocess, "run", return_value=self.fake(XML.encode(), 0, b"Warning: something")):
			self.assertEqual(run_nmap("example.test", []), XML)


class NmapScriptingTest(unittest.TestCase):
	def run_args(self, target, ports, scripts=None):
		s = nmap_scripting(target, ports, scripts)
		with mock.patch.object(nmap_scripts, "run_nmap", return_value=XML) as run:
			s.run()
		return run.call_args[0]

	def test_run_builds_arguments(self):
		# the host is kept as given (www. is part of it), -Pn skips ping
		self.assertEqual(self.run_args("http://www.example.test/app", "80 443"),
			("www.example.test", ["-Pn", "-p80,443", "--script", "http-methods"]))

	def test_target_port_is_scanned(self):
		# "host:8080/path" isn't a host nmap can resolve (#81): scan host, port 8080
		self.assertEqual(self.run_args("http://192.0.2.1:8080/insecure-bank", "80"),
			("192.0.2.1", ["-Pn", "-p80,8080", "--script", "http-methods"]))

	def test_target_port_not_repeated(self):
		self.assertEqual(self.run_args("https://example.test/", "80 443")[1][1], "-p80,443")

	def test_empty_ports_still_scan_the_target_port(self):
		# an empty port list used to give nmap a bare "-p" (#83)
		self.assertEqual(self.run_args("http://example.test:8080/", "")[1][1], "-p8080")

	def test_all_ports(self):
		self.assertEqual(self.run_args("https://example.test/", None, ["a", "b"]),
			("example.test", ["-Pn", "--script", "a", "--script", "b"]))

	def test_ipv6(self):
		self.assertEqual(self.run_args("http://[2001:db8::1]:8080/", "80"),
			("2001:db8::1", ["-Pn", "-6", "-p80,8080", "--script", "http-methods"]))


class NmapTargetTest(unittest.TestCase):
	def test_hosts_and_ports(self):
		self.assertEqual(nmap_target("http://Example.test:8080/a?b"), ("example.test", 8080))
		self.assertEqual(nmap_target("https://example.test"), ("example.test", 443))
		self.assertEqual(nmap_target("example.test/x"), ("example.test", 80))

	def test_rejects_unusable_targets(self):
		for url in ("http://-iLfoo/", "http:///path", "http://example.test:99999/"):
			with self.assertRaises(ValueError):
				nmap_target(url)


if __name__ == "__main__":
	unittest.main()
