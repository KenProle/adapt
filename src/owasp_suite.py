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

try:
	import re, subprocess, time, urllib.request, requests, random, copy, os
	import scipy.stats as stats
	import itertools, os, errno, json, signal, socket, ssl, sys, traceback
	from aprint import aprint
	from urllib.parse import urlparse
	from difflib import SequenceMatcher
	from wig.wig import wig
	# wig's HTMLStripper breaks on newer Pythons (issue #8)
	from wig_compat import patch_wig
	patch_wig()
	from bs4 import BeautifulSoup
	from bs4 import Comment 
	from httpparser.httprequest import HTTPRequest
	from collections import defaultdict
	from entropy import entropy
	from timeit import default_timer
	from error import error_suite
	from time import sleep
	from nmap_scripts import nmap_scripting
except Exception as e:
	import sys
	print("Cannot import module: "+str(e)+". Quitting...")
	sys.exit(1)

from pprint import pprint

def __type_check(val, t):
	if(type(val) == t):
		return True
	return False

def wait_min(count):
	sleep(count*60)

def create_report(name, basic_description="", severity="none", request="", confidence=1.0, misc=[], path="", cwe=None, related_cwes=[], preventions=[], owasp_association=None, error=False):

	if(not __type_check(name, str)):
		name = ""
	if(not __type_check(basic_description, str)):
		basic_description = ""
	if(not __type_check(severity, str)):
		severity = "none"
	if(severity != "low" and severity != "none" and severity!="medium" and severity!="high"):
		severity = "none"
	if(not __type_check(request, str)):
		request = ""
	if(not __type_check(confidence, float)):
		confidence = 1.0
	if(not __type_check(path, str)):
		paht = ""
	if(__type_check(misc, str)):
		misc = [misc]
	if(not __type_check(misc, list)):
		misc = []
	
	ret = {
		"name":name, 
		"basic_description":basic_description,
		"severity":severity,
		"request":request,
		"confidence":confidence,
		"misc":misc,
		"path":path,
		"cwe_id":cwe,
		"related_cwes":related_cwes,
		"preventions":preventions,
		"owasp_association":owasp_association,
		# True when the test itself failed to run; adapt_analysis lists
		# these under "errors" instead of treating them as findings
		"error":bool(error)
	}

	return ret

class owasp_suite():
	def __init__(self, args, zap):
		self.args = args
		self.zap = zap
		self.unstripped_target = self.args["adapt_general"]["target_name"]
		self.stripped_target = re.sub("http://", "", self.unstripped_target)
		self.stripped_target = re.sub("https://", "", self.stripped_target)
		self.dns_target = self.stripped_target.split(":")[0]
		self.printer = aprint(self.args["adapt_general"]["verbose"], "owasp_suite")

		self.get_cookies_cache = []
		self.zapReqHeader = None
		self.nmap_crawl_size = self.args["adapt_general"]["nmap_crawl_size"]
		self.nmap_results = []
		self.nmap_failed = False
		self.printer.aprint("Finished setup")

	def run(self):

		if(self.args["adapt_general"]["nmap_script_ports"] != "skip"):
			self.printer.aprint("Nmap Starting")
			nmap_scripter = nmap_scripting(self.unstripped_target, self.args["adapt_general"]["nmap_script_ports"])
			try:
				self.nmap_results = nmap_scripter.run()
			except Exception as nmap_exception:
				self.printer.aprint("NMAP SCRIPT FAILED: "+str(nmap_exception), 2)
				self.nmap_results = []
				self.nmap_failed = True
			self.printer.aprint("Nmap finished")
		else:
			self.nmap_results = []
			self.nmap_failed = True

		self.printer.aprint("Owasp starting")
		ret = []

		test_methods = ["sess_001", "sess_002", "authz_001", "authn_001", "authn_002", "config_002", "crypst_001", "crypst_002", "err_001", "err_002", "info_002", "inpval_001", "inpval_002", "inpval_003", "ident_004", "authn_003",  "config_006"]

		for i in test_methods:
			if(not self.args["owasp_general"]["tests_to_run"][i]):
				continue
			self.printer.aprint("Invoking test: {}...".format(i))
			internal = getattr(self, i)
			# One failing test must not take down the whole run: record the
			# failure as an error entry for this test and carry on.
			try:
				int_res = internal()
			except Exception as e:
				err = "{}: {}".format(type(e).__name__, e)
				tb = traceback.format_exc()
				self.printer.aprint("Runtime error with test {}: {}\n{}".format(i, err, tb), 2)
				# aprint is silent without --verbose, so always say it somewhere visible
				print("ADAPT: test {} failed and was skipped: {}".format(i, err), file=sys.stderr)
				ret.append(create_report(i, "ERROR: test {} failed to run: {}".format(i, err), misc=tb.splitlines(), error=True))
				continue
			if(int_res is None):
				self.printer.aprint("Test {} may not be implemented".format(i))
			elif(type(int_res) == list):
				ret += int_res
			else:
				ret.append(int_res)
		self.printer.aprint("DONE")

		self.printer.aprint("Owasp done")
		return ret

	def __sub_setup(self, *args):
		p = subprocess.Popen([i for i in args],
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		return p


	def info_002(self):
		w = wig(
			url=self.stripped_target,
			run_all=True,
			proxy="localhost:"+self.zap.port )
		# see github.com/jkyc/wig/blob/master/wig/wig.py#L284 for options
		# since the normal output format is slightly arcane, it may make more sense
		# to dump to a json file and re-import
		# alternatively, sort through results for OS and Platform
		w.run()
		res = w.get_results()
		ret = []
		for nt in res:
			#entry = nt._asdict()
			# asdict omits the name of the tuple. wig has some overlap and ambiguity
			# so we'll add the name of the named tuple
			#entry["class"] = type( nt ).__name__
			note = "Information Discovery"
			url = ""
			if( "note" in nt._fields ):
				note = nt.note
			else: note = type( nt ).__name__
			if( "url" in nt._fields ):
				path = nt.url
			else:
				path = None
			ret.append( create_report( "info_002", note,  severity="low", misc=[nt.__str__()], path=path ) )
		return ret

	def find_comments_in_html(self, html):
		# Sometimes there is a dict type that gets passed to this function
		if(type(html) != str):
			return []
		soup = BeautifulSoup( html, 'html.parser' )
		comments = soup.findAll(text=lambda text:isinstance(text, Comment))
		return comments

	def find_comments_in_html_by_urls(self, urls):
		res = []
		for url in urls:
			path = urlparse(url).path
			host = urlparse(url).hostname
			scheme = urlparse(url).scheme
			req = "GET {0} {1}/1.1\r\nhost: {2}\r\n\r\n".format(path, scheme, host)
			try:
				r = self.zap.send_request(req)
				html = str(r['responseBody'])
			except Exception as e:
				try:
					# Target may use a self-signed certificate; we only read the page
					html = requests.get(url, timeout=15, verify=False).text
				except Exception as e2:
					self.printer.aprint("config_002: could not fetch "+url+": "+str(e2), 1)
					continue
			if (html):
				comment_list = [str(c) for c in self.find_comments_in_html(html) if str(c).strip()]
				if comment_list:
					res.append({ "method":"GET", "url":url, "resp":html, "request":"GET "+url, "data":comment_list })
		return res

	def generate_comment_reports_by_msgs(self):
		report_list = []
		try:
			messages = self.zap.spider_messages()
		except Exception as e:
			# spider not run (no spider id) or ZAP error: nothing to report from ZAP
			self.printer.aprint("config_002: could not get spider messages: "+str(e), 1)
			return report_list

		# The same comment (copyright banners, framework markers, ...) often appears on
		# many pages. Report each distinct comment once, on the first URL it was seen,
		# and list the other URLs in misc.
		seen = {}
		for msg in messages:
			try:
				# Only HTML and XML (incl. SVG) can hold markup comments; parsing
				# images or scripts as HTML turns binary data and regex
				# fragments into fake comments.
				content_type = re.search(r"(?im)^content-type:\s*([^;\r\n]*)", str(msg.get('responseHeader', "")))
				if (content_type and not any(t in content_type.group(1).lower() for t in ("html", "xml"))):
					continue
				req = HTTPRequest.read_from_zap_message( msg )
				if (self.zapReqHeader is None):
					if (msg['requestHeader'] != None):
						self.zapReqHeader = msg['requestHeader']
						self.zapReqBody = msg['requestBody']
				comments = self.find_comments_in_html( str(msg['responseBody']) )
				url = req.write_url()
				request = req.write()
			except Exception as e:
				self.printer.aprint("config_002: skipping unparsable message: "+str(e), 1)
				continue
			for comment in comments:
				key = str(comment).strip()
				if (not key):
					continue
				if (key in seen):
					if (url not in seen[key]["urls"]):
						seen[key]["urls"].append(url)
				else:
					seen[key] = {"urls":[url], "request":request}

		for key, info in seen.items():
			misc = [key]
			if (len(info["urls"]) > 1):
				misc.append("Also found on: "+", ".join(info["urls"][1:]))
			report_list.append(create_report("config_002", "html comment - ZAP", severity="low", owasp_association="6", path=info["urls"][0], request=info["request"], misc=misc))
		return report_list

	def config_002(self):
		report_list = []
		sev = "low"
		req = None
		conf = 1.0

		# comments in zap urls
		temp = self.generate_comment_reports_by_msgs()
		if ( temp ):
			report_list = report_list + temp

		# comments in nmap urls
		if (self.nmap_crawl_size != None):
			p = self.__sub_setup("nmap", "--script", "http-errors", "--script-args", "httpspider.maxpagecount="+self.nmap_crawl_size, self.stripped_target)
		else:
			p = self.__sub_setup("nmap", "--script", "http-errors", self.stripped_target)

		ignore_nmap = False
		nmap_results = ""
		try:
			(out, err) = p.communicate(None, timeout=90)
			regular = out.decode("utf-8", "replace")
			nmap_results = regular
		except:
			ignore_nmap = True
			
		# nmap_results = "Found the following error pages: https://help.disqus.com/customer/portal/articles/466253-what-html-tags-are-allowed-within-comments-"
		if "Found the following error pages" in nmap_results and not ignore_nmap :
			urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', nmap_results)
			comments = self.find_comments_in_html_by_urls(urls)
			if comments:
				for c in comments:
					report = create_report("config_002", "Found comments in HTML of URLs - NMAP", "medium", c["request"], 1.0, c["data"])
					report_list.append(report)


		return report_list

	def ident_004(self):
		reports = []
		if(self.args["adapt_general"]["skip_authentication"]):
			return []
		#bad_pass = "thisIsNotARealPasswordButShouldBeAUniqueString"
		#bad_uname = "thisIsNotARealUsernameButAUniqueString"
		bad_pass = self.args["adapt_general"]["password"]+"_notValid"
		bad_uname = self.args["adapt_general"]["username"]+"_notValid"
		#baseurl = self.auth['login_url'] # easier to have this be a separate thing than strip it from method params
		#userdata = self.auth['userdata']
		#good_uname = userdata['Username']

		good_uname = self.args["adapt_general"]["username"]

		#bad_passwd_data = copy.deepcopy(userdata)
		#bad_passwd_data['Password'] = bad_pass
		#bad_uname_data = copy.deepcopy( bad_passwd_data )
		#bad_uname_data['Username'] = bad_uname
		reps = 30


		badpwd_msgs = []
		badun_msgs = []
		for i in range(0,reps):
			# Alternate which login goes first, so effects of request order
			# (warm-up, caching) don't show up as a timing difference
			if(i % 2 == 0):
				badpwd_msgs.append(self.zap.test_login(good_uname, bad_pass))
				badun_msgs.append(self.zap.test_login(bad_uname, bad_pass))
			else:
				badun_msgs.append(self.zap.test_login(bad_uname, bad_pass))
				badpwd_msgs.append(self.zap.test_login(good_uname, bad_pass))
			#badpwd_msgs.append( self.zapper.test_login( bad_passwd_data, "Bad Password" ) )
			#badun_msgs.append( self.zapper.test_login( bad_uname_data, "Bad Username" ))

		# Not sure what to do if this doesn't pass. But this crash will be easier to deal with than silently getting bad results
		assert( len( badpwd_msgs ) == reps )
		assert( len( badun_msgs ) == reps )

		'''
		#Theory:
		Responses for valid/invalid (v/i) login different than invalid/invalid (i/i) login
			ex. ("incorrect password" vs "that user does not exist" )
			OWASP-AT-002

		#To Test:
		Obtain responses for v/i attempts (call this badpwd_bodys = [vi1, vi2, vi3, ...] )
		Do a pairwise comparison of adjacent elements ( baseline_diffs = [d_vi12, d_vi23, d_vi31, ...] )
			Specifically, count similarity ratio. See difflib.SequenceMatcher for more
		Obtain responses for i/i attemps ( badun_bodys = [ii1, ii2, ii3, ...] )
		Do an elementwise comparison of vi1 to ii1, vi2 to ii2, etc ( test_diffs = [d1, d2, d3, ...] )

		Do a statistical analysis of baseline_diffs vs test_diffs
		'''
		# sub out username if present, to prevent that from making pages seem different
		badpwd_bodys1 = [re.sub( good_uname, "", str(msg['responseBody']) ) for msg in badpwd_msgs ] 
		#  copy and do a pairwise comparison
		badpwd_bodys2 = copy.copy( badpwd_bodys1 )
		badpwd_bodys2 = badpwd_bodys2[1:]
		badpwd_bodys2.append( badpwd_bodys1[0] )
		baseline_diffs = [ SequenceMatcher( None, b1, b2 ).ratio() for b1,b2 in zip( badpwd_bodys1, badpwd_bodys2 ) ]

		# get diffs for invalid logins
		badun_bodys = [re.sub( bad_uname, "", str(msg['responseBody'])) for msg in badun_msgs ]
		test_diffs = [ SequenceMatcher( None, b1, b2 ).ratio() for b1,b2 in zip( badpwd_bodys1, badun_bodys ) ]
		res = stats.ttest_ind( baseline_diffs, test_diffs, equal_var=False )

		if( res.pvalue < 0.05 ):
			reports.append( create_report( 'ident_004', basic_description="Response difference between valid and invalid usernames on login page", severity='low', request='', confidence=1.0, path=self.unstripped_target ) )

		# rtt analysis, same general methodology
		badpwd_rtts = [ float(msg['rtt']) for msg in badpwd_msgs ]
		avg_badpwd = sum( badpwd_rtts ) / len( badpwd_rtts )

		badun_rtts =  [ float(msg['rtt']) for msg in badun_msgs ]
		avg_badun = sum( badun_rtts ) / len( badun_rtts )
		res = stats.ttest_ind( badpwd_rtts, badun_rtts, equal_var=False )
		if( max( badpwd_rtts + badun_rtts ) < 1.0 ):
			# Almost certainly an auth module returning seconds, not milliseconds
			print("ADAPT: ident_004: every login rtt is under 1 ms; check that the auth module returns rtt in milliseconds", file=sys.stderr)
		# Require a difference big enough to matter as well as a significant
		# one: with millisecond precision, tiny systematic differences can be
		# "significant" without saying anything about the username. A fixed
		# floor, because the server-side work that gives a username away adds
		# a fixed amount of time however slow the network is.
		min_diff_ms = 5.0
		if( res.pvalue < 0.05 and abs( avg_badpwd - avg_badun ) >= min_diff_ms ):
			reports.append( create_report(
			'ident_004',
			basic_description="Timing difference observed between valid and invalid usernames",
			severity='low',
			request='',
			confidence=1.0,
			path=self.unstripped_target,
			cwe=521,
			owasp_association="2",
			misc=[
				# plain floats: scipy's result object is not JSON serialisable
				# (df only exists from scipy 1.11)
				{ "statistic": float( res.statistic ), "pvalue": float( res.pvalue ), "df": float( res.df ) if hasattr( res, "df" ) else None },
				"{} v/i attempts with average rtt of {:.1f} ms".format( len( badpwd_rtts), avg_badpwd ),
				"{} i/i attempts with average rtt of {:.1f} ms".format( len( badun_rtts), avg_badun )] ) )
			
		return reports
		
	def authn_001(self):
		msg = self.zap.test_login(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
		#req = HTTPRequest.read_from_zap_message(msg)
		#if('https://' in req.write_url()):
		#	return []
		if('https://' in msg["requestBody"] or 'https://' in msg["requestHeader"]):
			return []
		return create_report(
			"authn_001",
			basic_description="Credentials submitted over http",
			severity="medium",
			owasp_association="6",
			cwe=261,
			request=msg["requestHeader"]+msg["requestBody"]
		)

	def authn_002(self):
		reports = []

		# These are not exhaustive. May be better to read from a file
		# be aware that each test can take up to a second. Don't try with 100 x 100 unless you are leaving it for a weekend
		f = open(os.getcwd()+self.args["adapt_general"]["default_username_file"])
		usernames = f.read().split()
		f.close()

		f = open(os.getcwd()+self.args["adapt_general"]["default_password_file"])
		passwords = f.read().split()
		f.close()
		for u,p in itertools.product( usernames, passwords ):
			login_msg = self.zap.test_login(u, p)
			if(login_msg["successful"]):
				self.printer.aprint( "Default login {}/{} successful".format( u,p ) )
				reports.append( create_report( "authn_002", basic_description="Default Credentials: {}/{}".format( u,p ), severity="high", cwe=521, owasp_association="6", confidence=1.0, misc=[]) )

		
		return reports

	def authn_003(self):
		reports = []
		reps = 15

		correct_username = self.args["adapt_general"]["username"]
		correct_password = self.args["adapt_general"]["password"]
		incorrect_password = self.args["adapt_general"]["password"]+"_owasp"

		start = default_timer()

		msgs = []
		for i in range( 0, reps ):
			self.printer.aprint( "Lockout login {}/{}".format( i+1, reps ) )
			msg = self.zap.test_login(correct_username, incorrect_password)
			assert(not msg["successful"]) # raise exception, error?
		end = default_timer()
		self.printer.aprint( "{} reps took {} seconds".format( reps, end-start ) )
		# 10 attempts/sec is our threshold
		if( end-start < reps*0.1 ):
			reports.append( create_report(
				"authn_003",
				basic_description="Brute force @ {} requests/sec".format( (end-start)/15),
				severity="medium",
				confidence=1.0) )

		valid = self.zap.test_login(correct_username, correct_password)
		if(valid["successful"]):
			reports.append( create_report(
				"authn_003",
				basic_description="No account lockout after {} wrong requsts".format( reps ),
				severity="medium",
				cwe=307,
				owasp_association="2" ) )

		return reports
	def authz_001(self):
		# This is already done by zap
		return []
	def inpval_001(self):
		# This is already done by zap
		return []
	def inpval_002(self):
		# This is already done by zap
		return []
	def inpval_003(self):
		report_list = []
		results = []
		errors = 0

		# get and post are standardized, there is no error if they give a page
		# BLAH is not a real http verb. This makes some web servers give interesting errors
		methods = ["PUT", "TRACE", "CONNECT", "PROPFIND", "DELETE", "PATCH", "BLAH"]

		for m in methods:
			try:
				if(m == "CONNECT"):
					# ZAP's sendRequest API rejects CONNECT (it only knows
					# CONNECT as the proxy tunnel handshake), so send it
					# ourselves, in the authority form a real client uses.
					# Limitation: this bypasses ZAP, so ZAP's upstream proxy
					# settings don't apply and it isn't in ZAP's history.
					req, resp = self.__raw_connect()
				else:
					req = "{} {}/ HTTP/1.0\r\n\r\n".format(m, self.unstripped_target)
					resp = self.zap.send_request( req )
				status = int(resp["responseHeader"].split()[1])
			except Exception as e:
				errors += 1
				self.printer.aprint("inpval_003: {} request failed: {}".format(m, e), 1)
				results.append("{}: ERROR, not tested ({}: {})".format(m, type(e).__name__, e))
				continue

			results.append("{}: HTTP {}".format(m, status))
			html = str(resp['responseBody'])
			if(m == "CONNECT"):
				if(200 <= status < 300):
					# A 2xx alone doesn't prove a working tunnel (some frameworks
					# answer every method with 200), hence the lower confidence.
					report_list.append(create_report("inpval_003", "Server answered CONNECT with HTTP {}; it may act as an open proxy/tunnel (not verified).".format(status), severity="medium", request=req, cwe=441, owasp_association="6", confidence=0.5))
				continue
			if(status == 200):
				report_list.append(create_report("inpval_003", "Valid response from potentially vulnerable verbs.", severity="low", request=req, confidence=1.0))
				if( html ):
					soup = BeautifulSoup( html, 'html.parser' )
					if( soup.html ):
						msg = "Received unexpected HTML in response on uncommon HTTP methods"
						# misc is a truncated version of the page
						misc = str( soup.html )
						if( len( misc ) > 100 ):
							misc = misc[:97] + "..."
						report = create_report("inpval_003", msg, severity="low", request=req, cwe=285, confidence=1.0, misc=[misc])
						report_list.append( report )

		# Always record what each verb got back, including the ones that could not be sent
		desc = "HTTP verb tampering: response status per method"
		if(errors):
			desc += " ({} of {} methods could not be tested)".format(errors, len(methods))
		report_list.append(create_report("inpval_003", desc, severity="none", request=self.unstripped_target, confidence=1.0, misc=results))
		if(errors):
			# The summary is severity "none", so it can be filtered out (or shown
			# as "pass" at detail=low). Also record an error entry, which
			# adapt_analysis always reports.
			err = "{} of {} HTTP methods could not be tested".format(errors, len(methods))
			print("ADAPT: inpval_003: "+err, file=sys.stderr)
			report_list.append(create_report("inpval_003", "ERROR: inpval_003 incomplete: "+err, misc=[r for r in results if "ERROR" in r], error=True))
		return report_list

	def __raw_connect(self, timeout=10, max_bytes=65536):
		"""Send 'CONNECT host:port HTTP/1.1' straight to the target and return
		(request, {"responseHeader", "responseBody"}) shaped like a ZAP message."""
		u = urlparse(self.unstripped_target)
		https = (u.scheme == "https")
		host = u.hostname
		if(not host):
			raise Exception("target {} has no host name (use a full URL such as http://host:port/)".format(self.unstripped_target))
		port = u.port or (443 if https else 80)
		authority = "{}:{}".format("["+host+"]" if ":" in host else host, port)   # bracket IPv6 literals
		req = "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n".format(authority)

		sock = socket.create_connection((host, port), timeout=timeout)
		try:
			if(https):
				ctx = ssl.create_default_context()
				# pentest target: certificate problems are reported elsewhere
				ctx.check_hostname = False
				ctx.verify_mode = ssl.CERT_NONE
				sock = ctx.wrap_socket(sock, server_hostname=host)
			sock.sendall(req.encode("ascii"))
			data = b""
			# Read the response head; a server that accepts CONNECT keeps the
			# tunnel open, so never wait for the connection to close. An
			# overall deadline stops a server that drips bytes from stalling
			# the test; on timeout, use whatever status line already arrived.
			deadline = time.monotonic() + timeout
			while(b"\r\n\r\n" not in data and len(data) < max_bytes):
				remaining = deadline - time.monotonic()
				if(remaining <= 0):
					break
				sock.settimeout(remaining)
				try:
					chunk = sock.recv(4096)
				except socket.timeout:
					break
				if(not chunk):
					break
				data += chunk
			# Only the status line matters, so stop after the response head
			head, _, body = data.partition(b"\r\n\r\n")
		finally:
			sock.close()
		if(not head):
			raise Exception("no response to {}".format(req.splitlines()[0]))
		return req, {
			"responseHeader":head.decode("iso-8859-1"),
			"responseBody":body.decode("utf-8", "replace")
		}

	def config_006(self):

		if(not self.args["zap_general"]["spider_turned_on"]):
			# Report the skip visibly, so it can't look like a clean run
			msg = "config_006 skipped: it needs the ZAP spider (spider_scan = on)"
			print("ADAPT: "+msg, file=sys.stderr)
			return [create_report("config_006", "SKIPPED: "+msg, error=True)]

		report_list = []

		http_methods = []
		if(not self.nmap_failed):
			for i in self.nmap_results:
				if(type(i) == dict):
					if("http-methods" in i.keys()):
						http_methods.append(i["http-methods"])

		found_trace = False
		found_propfind = False

		for i in http_methods:
			if(not found_trace and "TRACE" in i) :
				found_trace = True
				report_list.append(
					create_report("config_006", "TRACE exists as a valid request verb, making service potentially vulnerable to XST attacks.", severity="medium", confidence=1.0, cwe=693)
				)
			elif(not found_propfind and "PROPFIND" in i):
				found_propfind = True
				report_list.append(
					create_report("config_006", "PROPFIND exists as a valid request verb, making service potentially vulnerable.", severity="medium",confidence=1.0, cwe=693)
				)


		# now we check for server responses 
		spider_urls = self.zap.spider_urls()
		enders = [".js", ".css", ".jpg", ".png", ".jpeg", ".html", ".ico"]
		ignore = False
		for i in range(len(spider_urls)):
			temp_url = spider_urls[i]["url"]
			ignore = False
			if(temp_url == self.unstripped_target):
				continue
			for j in enders:
				if(temp_url.endswith(j)):
					ignore = True

			if(ignore):
				continue
			new_req = "HEAD {} HTTP/1.0\r\n\r\n".format(temp_url)
			resp = self.zap.send_request(new_req)
			try:
				status_number = int(resp["responseHeader"].split()[1])
			except:
				self.printer.aprint("Malformed response: "+str(new_req), 1)
				continue
			if(status_number == 200):
				report_list.append(create_report("config_006", "Can access page. Please check to see if is allowable", severity="low", confidence=0.5, request=new_req))
			elif(status_number == 500):
				report_list.append(create_report("config_006", "Internal server error caused.",confidence=1.0, severity="medium", request=new_req, misc=[resp]))
			elif(status_number > 501):
				report_list.append(create_report("config_006", "Internal server error caused.", confidence=1.0, severity="medium", request=new_req, misc=[resp]))

		return report_list
		
	# Both err_001 and err_002 are handled by zap. 
	# err_001 was left completely to zap as zap handles specific server configurations 
	# and error reports from apache, microsoft, OLE DB, and tomcat 
	# https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsAscanrulesAscanrules
	# -> Parameter Tampering 
	def err_001(self):
		return []
	
	# this is also handled by zap
	def err_002(self):
		# Trying to run test cases to produce stack traces
		err = error_suite(self.args, self.zap)
		reports = err.run()
		count = len(reports)
		return reports
	def crypst_001(self):
		ret = []

		def not_tested(note):
			# Severity low (not "none") so the note survives risk filtering and
			# a skipped or failed TLS test can't look like a clean result.
			self.printer.aprint(note, 1)
			return [create_report(name, note, severity="low", owasp_association="6") for name in ("crypst_001", "crypst_002")]

		parsed = urlparse(self.unstripped_target)
		if(parsed.scheme.lower() != "https"):
			return not_tested("Target is not an https:// URL ({}), so no TLS configuration was tested (testssl.sh skipped)".format(self.unstripped_target))
		try:
			port = parsed.port or 443
		except ValueError:
			return not_tested("Target {} has an invalid port, so no TLS configuration was tested".format(self.unstripped_target))
		host = parsed.hostname
		if(not host):
			return not_tested("Could not find a host name in target {}, so no TLS configuration was tested".format(self.unstripped_target))
		if(":" in host):
			host = "["+host+"]"   # IPv6 literal
		testssl_target = host+":"+str(port)

		filename = os.getcwd()+"/tmp/ssl_test.json"
		failure = None
		testssl_results = None
		try:
			# testssl.sh refuses to overwrite an existing output file
			if(os.path.exists(filename)):
				os.remove(filename)
			# Own session, so a timeout can kill testssl.sh and its openssl children
			x = subprocess.Popen([os.getcwd()+self.args["adapt_general"]["testssl_loc"], "-oJ", filename, testssl_target],
				stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
			try:
				(out, err) = x.communicate(None, 1000)
			except BaseException:
				# Timeout, or Ctrl-C: testssl.sh runs in its own session, so
				# the terminal's SIGINT doesn't reach it; stop the whole group
				# rather than leave it scanning the target in the background.
				try:
					os.killpg(x.pid, signal.SIGKILL)
				except ProcessLookupError:
					pass   # already gone; re-raise the original exception, not this
				x.communicate()
				raise
			try:
				with open(filename) as datafile:
					testssl_results = json.load(datafile)
				if(not isinstance(testssl_results, dict)):
					raise ValueError("unexpected testssl.sh output")
			except Exception as e:
				# Show why testssl.sh failed, not just that its output was unreadable
				tail = err.decode("utf-8", "replace").strip()[-300:] or out.decode("utf-8", "replace").strip()[-300:]
				raise Exception("{}; testssl.sh exit code {}: {}".format(e, x.returncode, tail))
		except Exception as e:
			failure = str(e)
			testssl_results = None
		finally:
			try:
				os.remove(filename)
			except OSError:
				pass

		if(testssl_results is None):
			hint = ""
			# testssl.sh's message when no DNS tool is installed
			if(re.search(r'Neither "dig", "host"|\b(dig|drill|nslookup)\b.*not (present|found)', failure)):
				hint = " Install dig/host (package bind9-dnsutils or dnsutils)."
			return not_tested("testssl.sh failed against "+testssl_target+" ("+failure+"); TLS configuration was not tested."+hint)

		# newer testssl.sh versions put per-run info before the host result,
		# so find the entry that holds the actual host findings
		host_result = None
		for entry in testssl_results.get("scanResult", []):
			if(isinstance(entry, dict) and "protocols" in entry):
				host_result = entry
				break
		if(testssl_results.get("scanTime") == "Scan interrupted" or host_result is None):
			return not_tested("testssl.sh did not return results for "+testssl_target+" (scan interrupted or target unreachable); TLS configuration was not tested")

		blocks = ["grease", "ciphers", "pfs", "fs", "serverPreferences", "serverDefaults", "headerResponse", "cipherTests", "browserSimulations"]		
		
		padding_oracle_vulns = ["freak", "robot", "lucky13", "logjam", "logjam-common_primes", "poodle"]

		warning = "none"
		# check protocols 
		for i in host_result["protocols"]:
			warning = "none" 
			if(i["severity"] == "LOW"):
				warning = "low"
			elif(i["severity"] == "MEDIUM"):
				warning = "medium"
			elif(i["severity"] == "HIGH"):
				warning = "high"
			elif(i["severity"] == "CRITICAL"):
				warning = "high"
			ret.append(create_report("crypst_001", i["id"]+" is "+i["finding"], severity=warning, owasp_association="6", cwe=327))

		for i in host_result.get("vulnerabilities", []):
			warning = "none"
			padding_oracle = "crypst_001"
			try:
				cwe_id = int(i["cwe"].split("-")[1])
			except:
				cwe_id = 327
			for j in padding_oracle_vulns:
				if(i["id"].lower().startswith(j)):
					padding_oracle = "crypst_002"
					break
			if(i["severity"] == "LOW"):
				warning = "low"
			elif(i["severity"] == "MEDIUM"):
				warning = "medium"
			elif(i["severity"] == "HIGH"):
				warning = "high"
			elif(i["severity"] == "CRITICAL"):
				warning = "high"

			ret.append(create_report(padding_oracle, i["id"].lower()+" : "+i["finding"], severity=warning, cwe=cwe_id, owasp_association="6"))
		
		for name in blocks:
			for i in host_result.get(name, []):
				if(i["severity"] == "INFO" or i["severity"] == "OK"):
					ret.append(create_report("crypst_001", i["id"], severity="none", misc=[i["finding"]]))
				else:
					warning = "none"
					if(i["severity"] == "LOW"):
						warning = "low"
					elif(i["severity"] == "MEDIUM"):
						warning = "medium"
					elif(i["severity"] == "HIGH"):
						warning = "high"
					elif(i["severity"] == "CRITICAL"):
						warning = "high"
					ret.append(create_report("crypst_001", i["id"]+" : "+i["finding"], severity=warning, owasp_association="6", cwe=327))

		return ret
	def crypst_002(self):
		# This is handled by crypst_001
		return []
		
	def sess_002(self):
		reports = []
		cookies = self.__get_cookies(1)

		for c in cookies:
			for cname,cval in c.items():
				assert(cname == cval['name'])
				reports.append(create_report(
					"sess_002",
					basic_description="Cookie secure attributes is not set for cookie: {}".format(cname),
					severity="low",
					confidence=1.0,
					owasp_association="2",
					cwe=614,
					misc=["This may occur as a consequence of not using https"]
				))

		return reports

	def sess_001(self):
		cvalues = defaultdict( list)
		reports = []
		cookies = self.__get_cookies(30)
		for c in cookies:
			for cname,cval in c.items():
				assert(cname == cval['name'])
				cvalues[cname].append(cval['value'])
		for cname,cvals in cvalues.items():
			ent = entropy(cvals)
			self.printer.aprint(str(ent))
			if(ent < 20):
				reports.append(create_report("sess_001", 
					basic_description="Low entropy session cookie: {}".format(cname),
					confidence=1.0,
					severity="medium",
					owasp_association="2",
					cwe=565,
					misc=["Entropy heuristic only detects {} bits of entropy".format(ent)]))
		
		return reports

	def __get_cookies(self, num):
		existing = len(self.get_cookies_cache)
		if(existing >= num):
			return self.get_cookies_cache[:num]
		sessions = []
		for i in range(num):
			
			x = self.zap.get_session(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
			sessions.append(x)
		for s in sessions:
			self.get_cookies_cache.append(s[1][1])
		return self.__get_cookies(num)

