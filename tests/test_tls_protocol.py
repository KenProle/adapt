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

here = os.path.dirname(os.path.abspath(__file__))
for d in ("src", "bin", "lib", "var"):
	sys.path.insert(0, os.path.join(here, "..", d))

reason = ""
try:
	from owasp_suite import owasp_suite
except BaseException as e:   # owasp_suite exits if ADAPT's packages aren't installed
	owasp_suite = None
	reason = "owasp_suite needs ADAPT's venv: " + str(e)


@unittest.skipIf(owasp_suite is None, reason)
class TLSProtocolTest(unittest.TestCase):
	def test_https_connect_requires_tls_1_2(self):
		instance = owasp_suite.__new__(owasp_suite)
		instance.unstripped_target = "https://example.test/"
		sock = mock.Mock()
		sock.recv.return_value = b"HTTP/1.1 200 Connection Established\r\n\r\n"
		context = mock.Mock()
		context.wrap_socket.return_value = sock

		with mock.patch("owasp_suite.socket.create_connection", return_value=sock), \
				mock.patch("owasp_suite.ssl.create_default_context", return_value=context):
			instance._owasp_suite__raw_connect()

		self.assertEqual(context.minimum_version, owasp_suite.ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
	unittest.main()
