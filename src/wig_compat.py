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

# Runtime fixes for wig (github.com/jekyc/wig), which is unmaintained.
#
# wig's HTMLStripper subclasses html.parser.HTMLParser, but its __init__ calls
# self.reset() and sets convert_charrefs itself instead of calling
# HTMLParser.__init__(). Python 3.14 (and the script/noscript parsing fix
# backported to later patch releases of older branches, e.g. 3.13.15) added
# the "scripting" attribute, which only HTMLParser.__init__ sets and which is
# read on every start tag, so feeding any page to HTMLStripper raises
#   AttributeError: 'HTMLStripper' object has no attribute 'scripting'
# (issue #8). The patch runs HTMLParser.__init__ first and then wig's own
# __init__, so wig keeps setting up whatever it needs; repeating reset() and
# convert_charrefs is harmless.

from html.parser import HTMLParser


def patch_wig():
	"""Apply the fixes to the installed wig. Safe to call more than once.
	Returns False (instead of raising) if wig's layout isn't what we expect."""
	try:
		from wig.classes import request2
		stripper = request2.HTMLStripper
	except (ImportError, AttributeError):
		return False
	if getattr(stripper.__init__, "_adapt_patched", False):
		return True
	original_init = stripper.__init__

	def init(self, *args, **kwargs):
		HTMLParser.__init__(self, convert_charrefs=True)
		original_init(self, *args, **kwargs)

	init._adapt_patched = True
	stripper.__init__ = init
	return True
