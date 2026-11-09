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

# Writes ADAPT's results (JSON-like data: dicts, lists, tuples, str, int,
# float, bool, None) as XML for --output *.xml.
#
# The format matches what the dicttoxml package (1.7.16, called with
# attr_type=False) produced before it was replaced, so existing consumers of
# ADAPT's XML see no change, including its quirks:
# - <?xml version="1.0" encoding="UTF-8" ?> then a <root> element;
# - list entries are <item> elements, and a list directly inside a list is
#   written as <item > (with a space);
# - only & " ' < > are escaped in text; None is an empty element; booleans
#   are true/false in dict values but True/False inside lists; dates are
#   written with isoformat(); any other iterable is written like a list;
# - a dict key that isn't a valid XML name becomes n<key> if it is a number,
#   gets spaces turned into underscores if that makes it valid, or else is
#   written as <key name="...">.

import numbers
from collections.abc import Iterable
from functools import lru_cache
from xml.dom.minidom import parseString


def _escape(text):
	for char, entity in (("&", "&amp;"), ('"', "&quot;"), ("'", "&apos;"), ("<", "&lt;"), (">", "&gt;")):
		text = text.replace(char, entity)
	return text


@lru_cache(maxsize=None)
def _is_xml_name(name):
	try:
		parseString('<?xml version="1.0" encoding="UTF-8" ?><%s>foo</%s>' % (name, name))
		return True
	except Exception:
		return False


def _element_name(key):
	"""Returns (element name, attribute string) for a dict key."""
	key = _escape(key) if isinstance(key, str) else key
	if _is_xml_name(str(key)):
		return str(key), ""
	if str(key).isdigit():
		return "n%s" % key, ""
	try:
		return "n%s" % float(str(key)), ""
	except ValueError:
		pass
	underscored = key.replace(" ", "_")
	if _is_xml_name(underscored):
		return underscored, ""
	return "key", ' name="%s"' % key


def _text(value):
	if isinstance(value, str):
		return _escape(value)
	return str(value)


def _is_scalar(value):
	return isinstance(value, (numbers.Number, str))


def _is_list(value):
	return isinstance(value, Iterable) and not isinstance(value, (str, dict))


def _dict(obj):
	out = []
	for key, value in obj.items():
		name, attrs = _element_name(key)
		if isinstance(value, bool):
			out.append("<%s%s>%s</%s>" % (name, attrs, str(value).lower(), name))
		elif _is_scalar(value):
			out.append("<%s%s>%s</%s>" % (name, attrs, _text(value), name))
		elif hasattr(value, "isoformat"):
			out.append("<%s%s>%s</%s>" % (name, attrs, _escape(value.isoformat()), name))
		elif isinstance(value, dict):
			out.append("<%s%s>%s</%s>" % (name, attrs, _dict(value), name))
		elif _is_list(value):
			out.append("<%s%s>%s</%s>" % (name, attrs, _list(value), name))
		elif value is None:
			out.append("<%s%s></%s>" % (name, attrs, name))
		else:
			raise TypeError("Unsupported data type: %s (%s)" % (value, type(value).__name__))
	return "".join(out)


def _list(items):
	out = []
	for item in items:
		if _is_scalar(item):  # bool is a Number here, so it stays True/False
			out.append("<item>%s</item>" % _text(item))
		elif hasattr(item, "isoformat"):
			out.append("<item>%s</item>" % _escape(item.isoformat()))
		elif isinstance(item, dict):
			out.append("<item>%s</item>" % _dict(item))
		elif _is_list(item):
			out.append("<item >%s</item>" % _list(item))
		elif item is None:
			out.append("<item></item>")
		else:
			raise TypeError("Unsupported data type: %s (%s)" % (item, type(item).__name__))
	return "".join(out)


def to_xml(obj):
	"""Returns obj as UTF-8 encoded XML bytes."""
	if isinstance(obj, dict):
		body = _dict(obj)
	elif isinstance(obj, bool):
		body = "<item>%s</item>" % str(obj).lower()
	elif obj is None or _is_scalar(obj) or hasattr(obj, "isoformat"):
		body = _list([obj])
	elif _is_list(obj):
		body = _list(obj)
	else:
		raise TypeError("Unsupported data type: %s (%s)" % (obj, type(obj).__name__))
	return ('<?xml version="1.0" encoding="UTF-8" ?><root>%s</root>' % body).encode("utf-8")
