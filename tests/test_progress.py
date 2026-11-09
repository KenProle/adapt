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

import io
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from progress import ProgressBar


class FakeTTY(io.StringIO):
	def isatty(self):
		return True


class ProgressBarTest(unittest.TestCase):
	def lines(self, bar):
		return bar.stream.getvalue().splitlines()

	def test_format(self):
		bar = ProgressBar(maxval=100, stream=io.StringIO(), width=28)
		bar.start()
		bar.update(50)
		bar.finish()
		self.assertEqual(self.lines(bar), [
			"[                    ]   0%",
			"[==========          ]  50%",
			"[====================] 100%",
		])

	def test_unchanged_value_not_redrawn(self):
		bar = ProgressBar(maxval=100, stream=io.StringIO(), width=28)
		bar.update(10)
		bar.update(10)
		self.assertEqual(len(self.lines(bar)), 1)

	def test_clamps_out_of_range(self):
		bar = ProgressBar(maxval=10, stream=io.StringIO(), width=28)
		bar.update(-5)
		bar.update(50)
		self.assertEqual(self.lines(bar), [
			"[                    ]   0%",
			"[====================] 100%",
		])

	def test_zero_maxval(self):
		# err_002 with no spider messages
		bar = ProgressBar(maxval=0, stream=io.StringIO(), width=28)
		bar.start()
		bar.finish()
		self.assertEqual(self.lines(bar), ["[====================] 100%"])

	def test_fractional_value(self):
		# pscan passes a fraction of records left, not a percentage
		bar = ProgressBar(maxval=100, stream=io.StringIO(), width=28)
		bar.update(0.5)
		self.assertEqual(self.lines(bar), ["[                    ]   0%"])

	def test_tty_redraws_in_place(self):
		bar = ProgressBar(maxval=4, stream=FakeTTY(), width=28)
		bar.start()
		bar.update(2)
		bar.finish()
		out = bar.stream.getvalue()
		self.assertEqual(out.count("\r"), 3)
		self.assertTrue(out.endswith("100%\n"))
		self.assertEqual(out.count("\n"), 1)

	def test_default_width_fits_terminal(self):
		bar = ProgressBar(maxval=100, stream=io.StringIO())
		bar.update(100)
		line = self.lines(bar)[0]
		self.assertLessEqual(len(line), shutil.get_terminal_size((80, 24)).columns)
		self.assertTrue(line.endswith("] 100%"))


if __name__ == "__main__":
	unittest.main()
