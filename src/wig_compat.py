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
# wig's HTMLStripper subclasses html.parser.HTMLParser but its __init__ calls
# self.reset() instead of HTMLParser.__init__(). That only ever worked because
# HTMLParser.__init__ used to set nothing that reset() did not. Python 3.14
# (and the script/noscript parsing fix backported to later patch releases of
# older branches, e.g. 3.13.15) added the "scripting" attribute, set only in
# __init__ and read on every start tag, so feeding any page to HTMLStripper
# raises
#   AttributeError: 'HTMLStripper' object has no attribute 'scripting'
# (issue #8). Replacing __init__ with one that initialises HTMLParser properly
# fixes that, and changes nothing on Pythons without the attribute.

from html.parser import HTMLParser


def _html_stripper_init(self):
	# Same state the original __init__ set up, but via HTMLParser.__init__ so
	# that every attribute the running Python's HTMLParser expects exists.
	HTMLParser.__init__(self, convert_charrefs=True)
	self.strict = False
	self.tagtext = []


def patch_wig():
	"""Apply the fixes to the installed wig. Safe to call more than once."""
	from wig.classes import request2
	stripper = request2.HTMLStripper
	if stripper.__init__ is not _html_stripper_init:
		stripper.__init__ = _html_stripper_init
