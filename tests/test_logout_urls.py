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
import re
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
for d in ("src", "bin", "lib", "var"):
	sys.path.insert(0, os.path.join(here, "..", d))

try:
	import zap_interface
except BaseException:   # needs ADAPT's venv (zapv2)
	zap_interface = None


@unittest.skipIf(zap_interface is None, "zap_interface not importable")
class LogoutUrlsTest(unittest.TestCase):
	# ZAP matches context exclusions against the whole URL (Java regex; the
	# features used behave the same in Python's re)
	def excluded(self, url, context="http://h"):
		return re.fullmatch(zap_interface.logout_exclusion(context), url) is not None

	def test_logout_links_are_excluded(self):
		self.assertTrue(self.excluded("http://h:8080/insecure-bank/j_spring_security_logout",
			"http://h:8080/insecure-bank"))   # #67
		for url in ("http://h/Logout.php", "http://h/user/sign-out", "http://h/signout",
				"http://h/logoff", "https://h/auth/log_out", "http://h/LOGOUT.do",
				"http://h/doLogout.action", "http://h/userLogout", "http://h/performLogOff",
				"http://h/account/signOut", "http://h/signoff", "http://h/sign-off",
				"http://h/logoutUser", "http://h/logout?next=/home"):
			self.assertTrue(self.excluded(url), url)

	def test_other_pages_are_not(self):
		for url in ("http://h/dashboard", "http://h/catalog/blogoffers", "http://h/blog/outline",
				"http://h/dialogout", "http://h/login", "http://h/log_output.jsp",
				"http://h/log-outage", "http://h/list?log_offset=10", "http://h/sign-outlet",
				"http://h/login?logout", "http://h/a?next=/logout"):
			self.assertFalse(self.excluded(url), url)

	def test_only_under_the_context(self):
		# a logout word in the host or the context itself must not exclude everything
		self.assertFalse(self.excluded("http://signout-svc:8080/app/page", "http://signout-svc:8080/app"))
		self.assertTrue(self.excluded("http://signout-svc:8080/app/logout", "http://signout-svc:8080/app"))
		self.assertFalse(self.excluded("http://other/logout", "http://h"))


if __name__ == "__main__":
	unittest.main()
