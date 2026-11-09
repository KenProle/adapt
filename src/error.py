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
ERROR_SIGNATURES = [
	# Java: a stack frame (Tomcat prints them without "at "), an exception name
	r"[\w$.]+\([\w$]+\.java:\d+\)",
	r"\bjava\.[\w.$]+(?:Exception|Error)\b",
	r"Exception in thread \"",
	# Python
	r"Traceback \(most recent call last\)",
	# .NET
	r"\bSystem\.[\w.]+Exception\b",
	r"Server Error in '[^']*' Application",
	r"\.(?:cs|vb):line \d+",
	# PHP
	r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:.{0,300}?\.php(?:</b>)? on line (?:<b>)?\d+",
	r"Stack trace:\s*(?:<br\s*/?>)?\s*#0 ",
	# Ruby, Node.js
	r"\.rb:\d+:in `",
	r"\bat (?:[^\r\n()]+ \()?\S+\.js:\d+:\d+\)?",
	# Databases
	r"You have an error in your SQL syntax",
	r"\bORA-\d{5}\b",
	r"Unclosed quotation mark after the character string",
	r"\bSQLSTATE\[",
	r"Microsoft OLE DB Provider",
	r"\bPG::\w+Error\b",
	r"\bSQLite3?::\w*Exception\b",
]
_ERROR_RE = re.compile("|".join("(?:{})".format(p) for p in ERROR_SIGNATURES), re.IGNORECASE | re.DOTALL)

def find_error_signature(text):
	"""Return the first stack-trace or database-error text in text, or None."""
	m = _ERROR_RE.search(text or "")
	return m.group(0) if m else None

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

	def __failed(self, what, e):
		self.failures += 1
		if(self.first_failure is None):
			self.first_failure = "{}: {}: {}".format(what, type(e).__name__, e)

	#
	# Method to iterate over the Zap msgs to try to product exceptions via invalid input and SQL injections
	#
	def attack_url_via_get1_v2( self, ref_zapmsg ):
		from owasp_suite import create_report
		report_list = []
		ref_request = HTTPRequest.read( ref_zapmsg['requestHeader'] + ref_zapmsg['requestBody'] )
		# A trace that is already on the unmodified page wasn't caused by
		# these attacks
		ref_signature = find_error_signature( str(ref_zapmsg.get('responseBody', "")) )
		get1_attacks = [ "A"*2048, "" ]
		sqlInjectList = self.build_sql_injections()
		get1_attacks += sqlInjectList
		req_copy = ref_request.copy()
		for k,ref_val in req_copy.path_params.items():
			for atk in get1_attacks :
				req_copy.path_params[k] = atk
				req1 = req_copy.write()
				request_line = req1.split("\r\n")[0]
				try:
					resp = self.zapper.send_request( req1 )
				except Exception as e:
					self.__failed(request_line, e)
					continue
				if( status_code(resp.get('responseHeader')) is None ):
					self.__failed(request_line, ValueError("the response has no HTTP status line"))
					continue
				# Whatever the status: PHP and others often print errors
				# on a 200 page
				responseBody = str(resp.get('responseBody', ""))
				signature = find_error_signature( responseBody )
				if( signature and not ref_signature ):
					report = create_report("err_002", "Found exception in HTTP response", "medium", req1 , 1.0, ["Matched: "+signature, responseBody], owasp_association="6")
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
					self.__failed("spider message {}".format(i), e)
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

