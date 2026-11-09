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
# file) it writes a line each time the bar changes.

import shutil
import sys


class ProgressBar:
	def __init__(self, maxval=100, stream=None, width=None):
		self.maxval = maxval
		self.stream = stream if stream is not None else sys.stderr
		self.width = width
		self.last = None

	def _line(self, value):
		if self.maxval > 0:
			fraction = min(max(value / self.maxval, 0.0), 1.0)
		else:
			fraction = 1.0
		width = self.width or shutil.get_terminal_size((80, 24)).columns
		inner = max(width - 8, 10)  # room for "[", "]" and " 100%"
		filled = int(fraction * inner)
		return "[%s%s] %3d%%" % ("=" * filled, " " * (inner - filled), int(fraction * 100))

	def _draw(self, value):
		line = self._line(value)
		if line == self.last:
			return
		self.last = line
		try:
			tty = self.stream.isatty()
		except (AttributeError, ValueError):
			tty = False
		self.stream.write(("\r" + line) if tty else (line + "\n"))
		self.stream.flush()

	def start(self):
		self._draw(0)

	def update(self, value):
		self._draw(value)

	def finish(self):
		self._draw(self.maxval)
		try:
			if self.stream.isatty():
				self.stream.write("\n")
				self.stream.flush()
		except (AttributeError, ValueError):
			pass
