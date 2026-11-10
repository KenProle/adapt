#
#  Automated Dynamic Application Penetration Testing (ADAPT)
#
#  Copyright (C) 2018 Applied Visions - http://securedecisions.com
#
#  Written by Siege Technologies - http://www.siegetechnologies.com/
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

'''
----------------------------------
ADAPT ERROR GENERATING TEST CASES
----------------------------------
This python module is attempt to address the OTG-ERR-002 requirements defined in the OWASP Testing Guide.
Below are the general points in this penetration testing:
        1) Use Zap scans messages and URLs
        2) Run a suite of test cases on these urls with invalid input to try to cause an exception and/or stack trace
        returned back to the client.

The goal of this penetration testing is create an exception on the backend services so we can try to do stack analysis to
determine specific details about the application.
'''
import re
import sys
from httpparser.httprequest import HTTPRequest
from progress import ProgressBar

# Text that shows the server leaked an exception, a stack trace or a database
# error, rather than an ordinary error page. A bare "error" or "exception" is
# not enough: most 404 pages contain one of those words.
#
# The response comes from the target, which may be hostile. Every pattern
# starts with literal text and bounds each repeat, so a search stays linear
# in the body's length and a crafted page can't stall the scan (each one
# with an unbounded repeat took seconds on a 100 KB line).
ERROR_SIGNATURES = [
	# Java: a stack frame (Tomcat prints them without "at "), an exception name
	r"\([\w$]{1,256}\.java:\d{1,7}\)",
	r"\bjava\.[\w.$]{1,150}?(?:Exception|Error)\b",
	r"Exception in thread \"",
	# JDBC drivers outside java.*
	r"\b(?:org\.postgresql|com\.mysql|org\.mariadb|com\.microsoft\.sqlserver|oracle\.jdbc|org\.h2|org\.hsqldb|org\.sqlite)\.[\w.$]{1,150}?(?:Exception|Error)\b",
	# Python, including Werkzeug's debugger: "Traceback <em>(most recent call last)</em>"
	r"Traceback\s{0,5}(?:<\w{1,10}>\s{0,5})?\(most recent call last\)",
	# .NET
	r"\bSystem\.[\w.]{1,150}?Exception\b",
	r"Server Error in '[^'\r\n]{0,256}' Application",
	r"\.(?:cs|vb):line \d{1,7}",
	# PHP
	r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:.{0,200}?\.php(?:</b>)? on line (?:<b>)?\d{1,7}",
	r"Stack trace:\s{0,20}(?:<br\s{0,5}/?>\s{0,20})?#0 ",
	# Ruby (3.4+ quotes the method with ' instead of `), Node.js
	r"\.rb:\d{1,7}:in [`']",
	r"\.js:\d{1,7}:\d{1,7}\)",
	# Databases
	r"You have an error in your SQL syntax",
	r"\bORA-\d{5}\b",
	r"Unclosed quotation mark after the character string",
	r"Incorrect syntax near",
	r"syntax error at or near",
	r"unterminated quoted string at or near",
	r"\bSQLSTATE\[",
	r"\bSQLITE_ERROR\b",
	r"Microsoft OLE DB Provider",
	r"\bPG::\w{1,100}?Error\b",
	r"\bSQLite3?::\w{0,100}?Exception\b",
]
_ERROR_RE = re.compile("|".join("(?:{})".format(p) for p in ERROR_SIGNATURES), re.IGNORECASE | re.DOTALL)

# Only the start of a very large body is searched
MAX_SEARCH = 1000000

def find_error_signatures(text):
	"""Return the stack-trace and database-error texts in text, in order, without repeats."""
	found = {}
	for m in _ERROR_RE.finditer((text or "")[:MAX_SEARCH]):
		found.setdefault(m.group(0), None)
	return list(found)

def find_error_signature(text):
	"""Return the first stack-trace or database-error text in text, or None."""
	found = find_error_signatures(text)
	return found[0] if found else None

def status_code(response_header):
	"""Return the status code from a response's status line, or None."""
	m = re.match(r"\s*HTTP/\S+\s+(\d{3})\b", response_header or "")
	return int(m.group(1)) if m else None

class error_suite():
	#
	# Constructor
	#
	def __init__(self, args, zapper):
		self.zapper = zapper
		self.args = args
		# Failed requests are counted and skipped, so that one failure
		# doesn't throw away everything found so far
		self.failures = 0
		self.first_failure = None

	def __failed(self, what, reason):
		# Only a short request line and a reason: an exception's own text
		# can quote the whole request, session cookies included, and this
		# goes to stderr and into the report
		self.failures += 1
		if(self.first_failure is None):
			if(len(what) > 200):
				what = what[:200]+"..."
			self.first_failure = "{}: {}".format(what, reason)

	#
	# Method to iterate over the Zap msgs to try to product exceptions via invalid input and SQL injections
	#
	def attack_url_via_get1_v2( self, ref_zapmsg ):
		from owasp_suite import create_report
		report_list = []
		ref_request = HTTPRequest.read( ref_zapmsg['requestHeader'] + ref_zapmsg['requestBody'] )
		# Errors that are already on the unmodified page (a PHP notice, say)
		# weren't caused by these attacks; report only the new ones
		ref_signatures = set(find_error_signatures( str(ref_zapmsg.get('responseBody', "")) ))
		get1_attacks = [ "A"*2048, "" ]
		sqlInjectList = self.build_sql_injections()
		get1_attacks += sqlInjectList
		req_copy = ref_request.copy()
		for k,ref_val in req_copy.path_params.items():
			for atk in get1_attacks :
				request_line = "{} {} (parameter {})".format(req_copy.verb, req_copy.path, k)
				# One failed attack mustn't lose the findings so far
				try:
					req_copy.path_params[k] = atk
					req1 = req_copy.write()
					request_line = req1.split("\r\n")[0]
					resp = self.zapper.send_request( req1 )
					# Only checks that it is an HTTP response: the status
					# doesn't matter, since PHP and others often print
					# errors on a 200 page
					if( status_code(resp.get('responseHeader')) is None ):
						self.__failed(request_line, "the response has no HTTP status line")
						continue
					responseBody = str(resp.get('responseBody', ""))
					new = [s for s in find_error_signatures( responseBody ) if s not in ref_signatures]
				except Exception as e:
					self.__failed(request_line, type(e).__name__)
					continue
				if( new ):
					report = create_report("err_002", "Found exception in HTTP response", "medium", req1 , 1.0, ["Matched: "+new[0], responseBody], owasp_association="6")
					report_list.append( report )
			# Attack one parameter at a time: put this one back before the next
			req_copy.path_params[k] = ref_val
		return report_list


	#
	# Build basic SQL innjection list
	#
	def build_sql_injections(self):
		l = [ "' OR '1'='1' --", "\' OR\'1\'=\'1\' --", "' OR '1'='1' ({", "' OR '1'='1' /*", "' AND 1=2'", "1 or x=1", "\' OR x=1", "\' union select 1" ]
		return l

	def run(self):
		report_list = []
		# one call: each one costs a ZAP API request per spidered URL
		messages = self.zapper.spider_messages()
		if messages:
			bar = ProgressBar(maxval=len(messages))
			if(self.args["adapt_general"]["verbose"]):bar.start()
			for i in range(len(messages)):
				if(self.args["adapt_general"]["verbose"]):bar.update(i)
				try:
					reports = self.attack_url_via_get1_v2( messages[i] )
				except Exception as e:
					self.__failed("spider message {}".format(i), type(e).__name__)
					continue
				if (reports):
					report_list += reports
			if(self.args["adapt_general"]["verbose"]):bar.finish()

		if(self.failures):
			# Recorded as an error entry, so skipped requests can't look
			# like a clean result
			from owasp_suite import create_report
			msg = "err_002: {} request(s) failed and were skipped; the first: {}".format(self.failures, self.first_failure)
			print("ADAPT: "+msg, file=sys.stderr)
			report_list.append(create_report("err_002", "ERROR: "+msg, error=True))
		return report_list

