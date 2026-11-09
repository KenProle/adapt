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
import types
import unittest

here = os.path.dirname(os.path.abspath(__file__))
for d in ("src", "bin", "lib", "var"):
	sys.path.insert(0, os.path.join(here, "..", d))

try:
	import zap_interface
except BaseException:   # needs ADAPT's venv (zapv2)
	zap_interface = None


class FakeBar:
	def __init__(self, maxval=100, **kwargs):
		self.values = []
	def start(self):
		pass
	def update(self, value):
		self.values.append(round(value))
	def finish(self):
		pass


@unittest.skipIf(zap_interface is None, "zap_interface not importable")
class PscanProgressTest(unittest.TestCase):
	def run_pscan(self, counts):
		counts = iter(counts)
		class Pscan:
			@property
			def records_to_scan(self):
				return str(next(counts))
		bars = []
		def make_bar(**kwargs):
			bars.append(FakeBar(**kwargs))
			return bars[-1]
		zap = zap_interface.AdaptZap.__new__(zap_interface.AdaptZap)
		zap.printer = types.SimpleNamespace(aprint=lambda *a, **k: None)
		zap.args = {"adapt_general": {"verbose": True}}
		zap.already_opened = zap.already_connected = True
		zap.zap = types.SimpleNamespace(pscan=Pscan())
		saved = (zap_interface.ProgressBar, zap_interface.time.sleep)
		zap_interface.ProgressBar, zap_interface.time.sleep = make_bar, lambda s: None
		try:
			zap.pscan()
		finally:
			zap_interface.ProgressBar, zap_interface.time.sleep = saved
		return bars[0].values

	def test_progress_rises(self):
		self.assertEqual(self.run_pscan([10, 10, 6, 2, 0]), [0, 0, 40, 80])

	def test_records_arriving_never_move_the_bar_back(self):
		values = self.run_pscan([10, 4, 9, 3, 0])
		self.assertEqual(values, sorted(values))

	def test_nothing_to_scan(self):
		# a first read of 0 used to be the total, and a later count divided by it (#73)
		self.assertEqual(self.run_pscan([0, 5, 0]), [])


if __name__ == "__main__":
	unittest.main()
