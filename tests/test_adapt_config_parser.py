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

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "..", "bin"))

import adapt_config_parser


class AdaptConfigParserTest(unittest.TestCase):
	def test_ephemeral_zap_port_probe_binds_to_loopback(self):
		config_dir = os.path.dirname(here)
		with open(os.path.join(config_dir, "var", "configuration.json")) as config_file:
			contents = json.load(config_file)

		with tempfile.TemporaryDirectory() as temp_dir:
			shutil.copy(os.path.join(config_dir, "adapt.config"), temp_dir)
			old_cwd = os.getcwd()
			os.chdir(temp_dir)
			try:
				with mock.patch.object(adapt_config_parser.socket, "socket") as make_socket:
					sock = make_socket.return_value
					sock.getsockname.return_value = ("127.0.0.1", 12345)
					adapt_config_parser.get_config_defaults(contents)
				sock.bind.assert_called_once_with(("127.0.0.1", 0))
			finally:
				os.chdir(old_cwd)


if __name__ == "__main__":
	unittest.main()
