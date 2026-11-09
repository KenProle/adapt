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

# A minimal text progress bar, "[=====     ]  50%", written to stderr.
# On a terminal it redraws one line; when stderr is redirected (e.g. to a log
# file) it writes a line each time the bar changes. The width is fixed when the
# bar is created; on a very narrow terminal only the percentage is shown.

import shutil
import sys


class ProgressBar:
	def __init__(self, maxval=100, stream=None, width=None):
		self.maxval = maxval
		self.stream = stream if stream is not None else sys.stderr
		self.width = width or shutil.get_terminal_size((80, 24)).columns
		try:
			self.tty = self.stream.isatty()
		except (AttributeError, ValueError):
			self.tty = False
		self.last = None
		self.broken = False

	def _line(self, value):
		if self.maxval > 0:
			fraction = min(max(value / self.maxval, 0.0), 1.0)
		else:
			fraction = 1.0
		percent = "%3d%%" % int(fraction * 100)
		inner = self.width - 8  # room for "[", "]", " 100%" and the cursor
		if inner < 5:
			return percent  # too narrow for a bar
		filled = int(fraction * inner)
		return "[%s%s] %s" % ("=" * filled, " " * (inner - filled), percent)

	def _write(self, text):
		# A closed stderr (e.g. "2>&1 | head") must not stop the scan.
		if self.broken:
			return
		try:
			self.stream.write(text)
			self.stream.flush()
		except (OSError, ValueError):
			self.broken = True

	def _draw(self, value):
		line = self._line(value)
		if line == self.last:
			return
		self.last = line
		# ESC[K clears whatever was left of a longer previous line
		self._write(("\r" + line + "\x1b[K") if self.tty else (line + "\n"))

	def start(self):
		self._draw(0)

	def update(self, value):
		self._draw(value)

	def finish(self):
		self._draw(self.maxval)
		if self.tty:
			self._write("\n")
