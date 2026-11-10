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
	from owasp_suite import NMAP_ERROR_URL_PATTERN
except BaseException as e:   # owasp_suite exits if ADAPT's packages aren't installed
	NMAP_ERROR_URL_PATTERN = None
	reason = "owasp_suite needs ADAPT's venv: " + str(e)
else:
	reason = ""


@unittest.skipIf(NMAP_ERROR_URL_PATTERN is None, reason)
class NmapErrorUrlsTest(unittest.TestCase):
	def test_matches_url_reserved_characters(self):
		text = "http://example.test/a-b_~?x=1&y=$2;z=%20#fragment"
		self.assertEqual(re.findall(NMAP_ERROR_URL_PATTERN, text), [text])

	def test_stops_at_non_url_characters(self):
		text = "http://example.test/a<bad>^`\\"
		self.assertEqual(re.findall(NMAP_ERROR_URL_PATTERN, text), ["http://example.test/a"])


if __name__ == "__main__":
	unittest.main()
