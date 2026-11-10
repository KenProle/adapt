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
			"    at /app/server.js:10:5",
			"Traceback <em>(most recent call last)</em>",
			"app/models/user.rb:12:in 'Integer#/'",
			"app/models/user.rb:12:in `divide'",
			'ERROR: syntax error at or near "\'"',
			"Incorrect syntax near 'x'.",
			"org.postgresql.util.PSQLException: ERROR: unterminated quoted string",
			"com.mysql.cj.jdbc.exceptions.CommunicationsException",
		]:
			self.assertIsNotNone(error.find_error_signature(text), text)

	def test_all_signatures_found_once_each(self):
		text = "java.lang.NullPointerException ... java.lang.NullPointerException ... ORA-00933"
		self.assertEqual(error.find_error_signatures(text), ["java.lang.NullPointerException", "ORA-00933"])

	def test_linear_time_on_hostile_bodies(self):
		# 1 MB of each takes well under a second; with unbounded patterns some
		# took seconds at 100 KB and grew quadratically. 3 s allows for slow machines
		import time
		for body in ["A"*1000000, "foo at bar "*100000, "Stack trace:"+" "*1000000, "at "*300000, "java."*200000, "System."*150000, "Warning: "*100000, ".js:1:"*150000]:
			start = time.monotonic()
			error.find_error_signatures(body)
			self.assertLess(time.monotonic() - start, 3.0, body[:20])

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

	def test_error_that_echoes_the_input_is_not_new(self):
		def page(value):
			return "<b>Warning</b>: bad id '{}' in <b>/var/www/x.php</b> on line <b>3</b>".format(value)
		zap = FakeZap(lambda line: response(200, page(params(line).get("a", ""))))
		reports = error.error_suite(ARGS, zap).attack_url_via_get1_v2(message("/p?a=123", page("123")))
		self.assertEqual(reports, [])

	def test_signature_key(self):
		self.assertEqual(error.signature_key("Warning</b>: bad 'x' in <b>/a/x.php</b> on line <b>3"),
			error.signature_key("Warning</b>: other 'y' in <b>/a/x.php</b> on line <b>3"))
		self.assertEqual(error.signature_key("ORA-00001"), error.signature_key("ORA-00001", "1"))
		self.assertEqual(error.signature_key("near abc' OR x=1 here", "abc' OR x=1"), error.signature_key("near  here"))

	def test_same_error_with_another_line_is_new(self):
		zap = FakeZap(lambda line: response(200, "<b>Warning</b>: x in <b>/var/www/x.php</b> on line <b>9</b>"))
		notice = "<b>Warning</b>: x in <b>/var/www/x.php</b> on line <b>3</b>"
		reports = error.error_suite(ARGS, zap).attack_url_via_get1_v2(message("/p?a=1", notice))
		self.assertEqual(len(reports), len(zap.sent))

	def test_new_error_on_a_page_with_a_notice_is_reported(self):
		notice = "<b>Deprecated</b>: old() in <b>/var/www/x.php</b> on line <b>3</b>"
		def respond(line):
			if params(line).get("a") == "":
				return response(200, notice+" You have an error in your SQL syntax")
			return response(200, notice)
		reports = error.error_suite(ARGS, FakeZap(respond)).attack_url_via_get1_v2(message("/p?a=1", notice))
		self.assertEqual(len(reports), 1)
		self.assertEqual(reports[0]["misc"][0], "Matched: You have an error in your SQL syntax")


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

	def test_failure_text_is_short_and_has_no_exception_text(self):
		def respond(line):
			raise Exception("ZAP said: GET /p HTTP/1.1\r\nCookie: JSESSIONID=secret")
		reports = error.error_suite(ARGS, FakeZap(respond, [message("/p?a=1")])).run()
		self.assertEqual(len(reports), 1)
		text = reports[0]["basic_description"]
		self.assertNotIn("secret", text)
		self.assertLess(len(text), 400)    # the "A"*2048 request line is cut short

	def test_failure_text_has_no_query_or_path_params(self):
		def respond(line):
			raise Exception("down")
		reports = error.error_suite(ARGS, FakeZap(respond, [message("/p;jsessionid=SECRET1?sid=SECRET2&a=1")])).run()
		text = reports[-1]["basic_description"]
		self.assertNotIn("SECRET", text)
		self.assertIn("GET /p (parameter", text)

	def test_stops_after_failures_in_a_row(self):
		def respond(line):
			raise Exception("ZAP is gone")
		zap = FakeZap(respond, [message("/p{}?a=1&b=2".format(i)) for i in range(10)])
		reports = error.error_suite(ARGS, zap).run()
		self.assertEqual(len(zap.sent), error.MAX_FAILURES_IN_A_ROW)
		self.assertEqual(len(reports), 1)
		self.assertIn("stopped after", reports[0]["basic_description"])

	def test_a_success_resets_the_count(self):
		# every other request fails: never 20 in a row, so every page is tried
		def respond(line):
			p = params(line)
			if p.get("a", "x") == "" or p.get("a", "").startswith("'"):
				raise Exception("flaky")
			return response(200, "ok")
		zap = FakeZap(respond, [message("/p{}?a=1".format(i)) for i in range(10)])
		reports = error.error_suite(ARGS, zap).run()
		self.assertEqual(len(zap.sent), 10 * 10)
		self.assertNotIn("stopped", reports[-1]["basic_description"])

	def test_a_failure_while_writing_keeps_the_page_findings(self):
		zap = FakeZap(lambda line: response(500, TOMCAT_500))
		suite = error.error_suite(ARGS, zap)
		msg = message("/p?a=1&b=2")
		real_write = error.HTTPRequest.write
		def write(req):
			if req.path_params.get("b") == "":
				raise ValueError("cannot write")
			return real_write(req)
		error.HTTPRequest.write = write
		try:
			reports = suite.attack_url_via_get1_v2(msg)
		finally:
			error.HTTPRequest.write = real_write
		attacks = 2 + len(suite.build_sql_injections())
		self.assertEqual(len(reports), 2 * attacks - 1)
		self.assertEqual(suite.failures, 1)

	def test_no_error_entry_when_nothing_failed(self):
		zap = FakeZap(lambda line: response(200, "ok"), [message("/p?a=1")])
		self.assertEqual(error.error_suite(ARGS, zap).run(), [])


if __name__ == "__main__":
	unittest.main()
