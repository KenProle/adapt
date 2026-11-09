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
import urllib.parse

here = os.path.dirname(os.path.abspath(__file__))
for d in ("src", "bin", "lib", "var"):
	sys.path.insert(0, os.path.join(here, "..", d))

import error

TOMCAT_500 = """<html><head><title>HTTP Status 500 - Internal Server Error</title></head><body>
<p><b>Type</b> Exception Report</p><pre>org.springframework.web.util.NestedServletException: Request processing failed; nested exception is java.lang.IndexOutOfBoundsException: Index 0 out of bounds for length 0
	org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:982)
</pre></body></html>"""

PLAIN_404 = "<html><head><title>404 Error</title></head><body>Error: page not found. An exception occurred.</body></html>"


def fake_create_report(name, basic_description="", severity="none", request="", confidence=1.0, misc=[], path="", cwe=None, related_cwes=[], preventions=[], owasp_association=None, error=False):
	return {"name": name, "basic_description": basic_description, "request": request, "misc": misc, "error": error}


class FakeZap:
	"""Answers send_request with whatever respond(request line) returns."""
	def __init__(self, respond, messages=()):
		self.respond = respond
		self.messages = list(messages)
		self.sent = []
	def send_request(self, request):
		self.sent.append(request)
		return self.respond(request.split("\r\n")[0])
	def spider_messages(self):
		return self.messages


def message(url, body="ok"):
	return {"requestHeader": "GET {} HTTP/1.1\r\nHost: t\r\n\r\n".format(url), "requestBody": "",
		"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": body}

def response(status, body):
	return {"responseHeader": "HTTP/1.1 {} X\r\nContent-Type: text/html\r\n".format(status), "responseBody": body}

def params(request_line):
	query = request_line.split()[1].partition("?")[2]
	return dict(urllib.parse.parse_qsl(query, keep_blank_values=True))

ARGS = {"adapt_general": {"verbose": False}}


class ErrorTestBase(unittest.TestCase):
	def setUp(self):
		# error.py imports create_report from owasp_suite, which needs ZAP's
		# client; a stand-in keeps these tests free of ADAPT's venv
		self.saved = sys.modules.get("owasp_suite")
		sys.modules["owasp_suite"] = types.SimpleNamespace(create_report=fake_create_report)
		self.stderr = sys.stderr
		sys.stderr = open(os.devnull, "w")
	def tearDown(self):
		sys.stderr.close()
		sys.stderr = self.stderr
		if self.saved is None:
			del sys.modules["owasp_suite"]
		else:
			sys.modules["owasp_suite"] = self.saved


class TestSignatures(unittest.TestCase):
	def test_stack_traces_and_database_errors_match(self):
		for text in [
			TOMCAT_500,
			"\tat com.example.Foo.bar(Foo.java:12)",
			'Traceback (most recent call last):\n  File "app.py", line 3',
			"System.NullReferenceException: Object reference not set",
			"<b>Warning</b>:  mysqli_query() in <b>/var/www/x.php</b> on line <b>12</b>",
			"PHP Fatal error:  Uncaught Error in /var/www/a.php on line 9",
			"You have an error in your SQL syntax; check the manual",
			"ORA-00933: SQL command not properly ended",
			"    at Object.<anonymous> (/app/server.js:10:5)",
		]:
			self.assertIsNotNone(error.find_error_signature(text), text)

	def test_ordinary_error_pages_do_not_match(self):
		for text in [PLAIN_404, "", None, "Warning: your session will expire", "javascript error handler", "see line 4 of the form"]:
			self.assertIsNone(error.find_error_signature(text), text)

	def test_status_code(self):
		self.assertEqual(error.status_code("HTTP/1.1 500 Internal Server Error\r\n"), 500)
		self.assertEqual(error.status_code("HTTP/2 404\r\n"), 404)
		self.assertIsNone(error.status_code("garbage"))
		self.assertIsNone(error.status_code(""))
		self.assertIsNone(error.status_code(None))


class TestAttack(ErrorTestBase):
	def test_one_parameter_attacked_at_a_time(self):
		zap = FakeZap(lambda line: response(200, "ok"))
		error.error_suite(ARGS, zap).attack_url_via_get1_v2(message("/p?a=1&b=2"))
		attacks = 2 + len(error.error_suite(ARGS, zap).build_sql_injections())
		self.assertEqual(len(zap.sent), 2 * attacks)
		for i, req in enumerate(zap.sent):
			p = params(req.split("\r\n")[0])
			if i < attacks:
				self.assertEqual(p["b"], "2")    # b untouched while a is attacked
			else:
				self.assertEqual(p["a"], "1")    # a restored before b is attacked

	def test_reports_stack_trace_not_plain_error_page(self):
		def respond(line):
			p = params(line)
			if p.get("a") == "":
				return response(500, TOMCAT_500)
			return response(404, PLAIN_404)
		reports = error.error_suite(ARGS, FakeZap(respond)).attack_url_via_get1_v2(message("/p?a=1"))
		self.assertEqual(len(reports), 1)
		self.assertTrue(reports[0]["misc"][0].startswith("Matched: "))
		self.assertFalse(reports[0]["error"])

	def test_trace_on_200_page_is_reported(self):
		zap = FakeZap(lambda line: response(200, "You have an error in your SQL syntax"))
		reports = error.error_suite(ARGS, zap).attack_url_via_get1_v2(message("/p?a=1"))
		self.assertEqual(len(reports), len(zap.sent))

	def test_trace_already_on_the_page_is_not_reported(self):
		zap = FakeZap(lambda line: response(500, TOMCAT_500))
		reports = error.error_suite(ARGS, zap).attack_url_via_get1_v2(message("/p?a=1", TOMCAT_500))
		self.assertEqual(reports, [])


class TestFailures(ErrorTestBase):
	def test_failed_requests_keep_other_results(self):
		def respond(line):
			p = params(line)
			if p.get("a") == "":
				raise Exception("ZAP sendRequest failed")
			if p.get("a", "").startswith("AAAA"):
				return {"responseHeader": "HTTP/1.1", "responseBody": ""}   # too short to hold a status
			return response(500, TOMCAT_500)
		zap = FakeZap(respond, [message("/p?a=1"), {"requestHeader": "nonsense"}, message("/q?a=1")])
		reports = error.error_suite(ARGS, zap).run()
		findings = [r for r in reports if not r["error"]]
		errors = [r for r in reports if r["error"]]
		per_page = len(error.error_suite(ARGS, zap).build_sql_injections())
		self.assertEqual(len(findings), 2 * per_page)
		self.assertEqual(len(errors), 1)
		# 2 failed requests per page, plus the message that couldn't be read
		self.assertIn("5 request(s) failed", errors[0]["basic_description"])

	def test_no_error_entry_when_nothing_failed(self):
		zap = FakeZap(lambda line: response(200, "ok"), [message("/p?a=1")])
		self.assertEqual(error.error_suite(ARGS, zap).run(), [])


if __name__ == "__main__":
	unittest.main()
