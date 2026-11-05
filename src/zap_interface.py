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

import os, sys, stat, contextlib, tempfile, time, datetime, logging, subprocess, json, html, urllib, urllib.error, urllib.parse, urllib.request, re, importlib, socket
#from httpparser.httprequest import HTTPRequest
from zapv2 import ZAPv2
from aprint import aprint
import progressbar

class AdaptZap():
	# Seconds to wait for ZAP's API to come up before giving up
	ZAP_STARTUP_TIMEOUT = 180

	def __init__(self, args):
		self.args = args
		self.printer = aprint(self.args["adapt_general"]["verbose"], "zap_interface")

		self.host = self.args["zap_general"]["host"]
		self.port = self.args["zap_general"]["port"]
		self.api_key = self.args["zap_general"]["api_key"]
		if(self.api_key is None):
			self.api_key = self.gen_random_api_key()

		self.zap_path = self.args["zap_general"]["path"]
		self.zap_opts = self.args["zap_general"]["opts"]
		self.close_on_finish = self.args["zap_general"]["close_on_finish"]
		self.target = self.args["adapt_general"]["target_name"]
		self.context = self.args["adapt_general"]["context_name"]

		self.already_connected = False
		self.already_opened = False

		# this is the spearate zap process 
		self.p = None

		self.context_name = "ADAPT Context"
		self.session_counter = 0
		self.spiderid = None

		if(not self.open()):
			raise Exception("Could not open zap")
		if(not self.connect()):
			raise Exception("Unable to establish zap proxy")

		self.contextid = self.__setup_context(self.args["zap_general"]["excluded"], self.context_name)

		# Attempt to use login function as test of verified ability 
		try:
			#self.auth_module.service_auth(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
			self.auth_module = importlib.import_module(self.args["adapt_general"]["auth_module"][:-3])
			self.create_new_session(self.args["adapt_general"]["username"], self.args["adapt_general"]["password"])
			self.auth_success = True
			self.printer.aprint("Authentication succeeded")
		except Exception as e:
			self.printer.aprint("Authentication failed: "+str(e), 1)
			self.auth_success = False

		self.printer.aprint("Finished setup")

	def get_results(self):
		return {
			"hosts":self.zap.core.hosts,
			"sites":self.zap.core.sites,
			"urls":self.zap.core.urls(),
			"alerts":self.zap.core.alerts()
		}

	def spider_messages(self):
		if(self.spiderid is None):
			return []   # the spider didn't run (spider_scan = off)
		in_scope_results = self.zap.spider.full_results(self.spiderid)[0]['urlsInScope']
		messages = []
		for res in in_scope_results:
			messages.append(self.zap.core.message(id=res["messageId"]))
		return messages

	def spider_urls(self):
		if(self.spiderid is None):
			return []
		return self.zap.spider.full_results(self.spiderid)[0]["urlsInScope"]

	def send_request(self, request):
		resp = self.zap.core.send_request(request)
		if( not isinstance(resp, list) or not isinstance(resp[0], dict)):
			# Only the request line: the rest may hold session cookies, and
			# this message can end up in the report's errors list
			raise Exception("ZAP sendRequest failed for request {!r}: expected a ZAP message, got: {}".format(request.split("\r\n")[0], resp))
		return resp[0]

	def create_new_session(self, username, password):
		new_sess = self.get_session(username, password)[0]
		return chain_zap_ops([
			lambda:self.zap.forcedUser.set_forced_user_mode_enabled(False),
			lambda:self.zap.httpsessions.set_active_session(self.target, new_sess)
		])

	def gen_random_api_key(self):
		from string import ascii_letters,digits
		from secrets import choice
		char_pool = ascii_letters + digits
		return ''.join(choice(char_pool) for i in range(32))

	def __sess_val(self):
		self.session_counter+=1
		return "session"+str(self.session_counter)

	def test_login(self, username, password, uid_name="test_logins"):
		return self.auth_module.service_auth(username, password)

	def get_session(self, username, password):
		for i in range(0,3):
			preexisting_sessions = self.zap.httpsessions.sessions(self.target)
			login_msg = self.test_login(username, password)
			if(login_msg == None):
				raise Exception("Error in authentication")
			if(login_msg["successful"] == True):
				new_sess = self.__sess_val()
				self.zap.httpsessions.create_empty_session(self.target, new_sess)
				for key,value in login_msg["cookies"].items():
					self.zap.httpsessions.add_session_token(self.target, key)
					self.zap.httpsessions.set_session_token_value(self.target, new_sess, key, value)
				new_sessions = self.zap.httpsessions.sessions(self.target)
				assert(len(preexisting_sessions) == len(new_sessions)-1)
				return (new_sess, new_sessions[-1]['session'])
			raise Exception("Cannot authenticate after 3 attempts, either login script is incorrect or ZAP has changed this user's password in the database.")

	def __del__(self):
		self.close()

	def close_zap_process(self):
		# Used when startup fails: stop the ZAP we launched, whatever close_on_finish says
		if(self.p is not None and self.p.poll() is None):
			self.p.kill()
			self.p.wait()

	def close(self):
		self.already_connected = False
		self.already_opened = False
		if(self.p is not None and self.close_on_finish):
			self.p.kill()
			self.p.wait()

	def __setup_context(self, excluded_paths, context_name):
		contextid = self.zap.context.new_context(context_name)
		self.zap.context.include_in_context(context_name, self.context+".*")
		for e in excluded_paths:
			self.printer.aprint("Excluded path: {}".format(e))
			self.zap.context.exclude_from_context(context_name, "{}{}".format(self.context,e))
		return contextid

	def __wait_for_api(self, version_url, opener, start):
		next_report = 15
		launcher_exited = False
		while(True):
			exit_code = self.p.poll()
			if(exit_code is not None and not launcher_exited):
				if(exit_code != 0):
					raise Exception("ZAP exited during startup (exit code {}). Check that {} runs on its own and that Java 17+ is installed.".format(exit_code, self.zap_path))
				# A launcher that starts ZAP in the background and exits 0:
				# keep polling the API instead of treating it as a failure.
				launcher_exited = True
				msg = "the ZAP launch command exited (code 0); assuming it started ZAP in the background. ADAPT can't stop that ZAP process itself."
				print("ADAPT: "+msg, file=sys.stderr)
			try:
				with opener.open(version_url, timeout=2) as resp:
					return json.loads(resp.read().decode("utf-8"))["version"]
			except urllib.error.HTTPError as e:
				if(e.code in (400, 401, 403)):
					# ZAP is up but refused the request (e.g. API key rejected):
					# waiting won't help, so stop with the real reason.
					raise Exception("ZAP is running on {}:{} but its API refused the request: HTTP {} {}".format(self.host, self.port, e.code, e.reason))
				# other statuses (e.g. 5xx while starting): keep waiting
				e.close()
			except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout):
				pass   # not listening yet
			elapsed = time.monotonic() - start
			if(elapsed > self.ZAP_STARTUP_TIMEOUT):
				extra = " The launch command had exited with code 0." if launcher_exited else ""
				raise Exception("ZAP did not answer on {}:{} within {} seconds; giving up.{}".format(self.host, self.port, self.ZAP_STARTUP_TIMEOUT, extra))
			if(elapsed > next_report):
				self.printer.aprint("Still waiting for ZAP ({:.0f}s)...".format(elapsed))
				next_report += 15
			time.sleep(1)

	def __write_api_key_file(self, directory=None):
		# ZAP applies the key=value lines of a -configfile at startup. Passing the
		# API key this way keeps it off the command line, where any local user
		# could read it with ps. mkstemp creates the file readable by us only; it
		# goes in ZAP's private -dir when there is one, so even if ADAPT is killed
		# before removing it, it isn't left in a shared /tmp.
		# Java properties format: \uXXXX-escape (UTF-16 units) everything but ASCII
		# letters and digits, so backslashes, '#', '=' or spaces in a configured key survive
		escaped = ""
		for c in self.api_key:
			if(c.isascii() and c.isalnum()):
				escaped += c
			else:
				units = c.encode("utf-16-be")
				escaped += "".join("\\u{:02x}{:02x}".format(units[i], units[i+1]) for i in range(0, len(units), 2))
		# Create the file only once the content is ready, so a failure above leaves nothing behind
		fd, path = tempfile.mkstemp(prefix="adapt-zap-", suffix=".properties", dir=directory)
		try:
			with os.fdopen(fd, "w", encoding="ascii") as f:
				f.write("api.key="+escaped+"\n")
		except BaseException:
			os.remove(path)
			raise
		return path

	def __protect_zap_home(self):
		# ZAP saves the API key in <dir>/config.xml (and logs it in <dir>/zap.log),
		# and the scanned traffic (cookies, credentials) under <dir>/db, all readable
		# by every local user with the usual umask. Keep its -dir private to us, and
		# don't start ZAP if that isn't possible (e.g. on a /mnt/c drive in WSL, or
		# a directory owned by someone else, which could also hold a planted config).
		opts = list(self.zap_opts)
		if("-dir" not in opts or opts.index("-dir")+1 >= len(opts)):
			return None
		zap_home = opts[opts.index("-dir")+1]
		try:
			os.makedirs(zap_home, mode=0o700, exist_ok=True)
			os.chmod(zap_home, 0o700)
			st = os.stat(zap_home)
		except OSError as e:
			raise Exception("Could not make ZAP's directory {} private: {}".format(zap_home, e))
		if(not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077) != 0):
			raise Exception("ZAP's directory {} must be a directory owned by you with mode 0700 (it is uid {}, mode {:o}), "
				"or other local users could read ZAP's API key and session data. Run ADAPT from a Linux filesystem you own "
				"(not e.g. /mnt/c in WSL).".format(zap_home, st.st_uid, stat.S_IMODE(st.st_mode)))
		return zap_home

	def open(self):
		self.printer.aprint("open zap daemon "+str(self.zap_path))
		zap_home = self.__protect_zap_home()
		key_file = None
		try:
			key_file = self.__write_api_key_file(zap_home)
			# An argument list, not a shell command, so nothing in the path or
			# opts is interpreted by a shell
			zap_cmd = [self.zap_path] + list(self.zap_opts) + ["-configfile", key_file, "-port", str(self.port)]
			try:
				self.p = subprocess.Popen(zap_cmd, stdout=subprocess.DEVNULL)
			except OSError as e:
				raise Exception("Could not start ZAP ({}). Check that zap_general.path in var/configuration.json points to an executable zap.sh.".format(e))
			self.printer.aprint("Waiting for zap startup... ")

			# Poll ZAP's API until it answers, instead of sleeping a fixed time:
			# stop early if the ZAP process exits, and give up after a timeout.
			version_url = "{}:{}/JSON/core/view/version/?{}".format(self.host, self.port, urllib.parse.urlencode({"apikey": self.api_key}))
			no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
			start = time.monotonic()
			version = self.__wait_for_api(version_url, no_proxy, start)
		except BaseException:
			# Any failure while starting (including Ctrl-C or an unexpected
			# reply) stops the ZAP we launched instead of leaving it running.
			self.close_zap_process()
			raise
		finally:
			# ZAP has read the key file by the time its API answers (or we have given up)
			if(key_file is not None):
				with contextlib.suppress(FileNotFoundError):
					os.remove(key_file)

		self.printer.aprint("ZAP {} ready after {:.0f}s".format(version, time.monotonic() - start))
		self.already_opened = True
		return True

	def connect(self):
		px = {"http":self.host+":"+self.port, "https":self.host+":"+self.port}
		self.printer.aprint("Connecting to zap... ")
		self.zap = ZAPv2(apikey=self.api_key, proxies=px)
		self.printer.aprint("Opening url")
		self.zap.urlopen(self.target, timeout=5)
		self.already_connected = True
		return True

	def check(self):
		assert(self.already_opened)
		assert(self.already_connected)

	def spider(self):
		self.printer.aprint("Spider start")
		self.check()
		self.printer.aprint(self.context_name)
		scanid = self.zap.spider.scan(self.target, contextname=self.context_name)

		if("not in the required context" in scanid):
			pass
		self.spiderid = scanid

		self.printer.aprint("scanid: "+str(scanid))

		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])

		if(self.args["adapt_general"]["verbose"]):bar.start()
		while(True):
			scan_progress = int(self.zap.spider.status(scanid))
			if(self.args["adapt_general"]["verbose"]):bar.update(scan_progress)
			if(scan_progress >= 100):
				break
			time.sleep(1)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Spider done")

	def pscan(self):
		self.printer.aprint("Pscan start")
		self.check()
		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		self.printer.aprint("This could take a while. Please be patient.")
		if(self.args["adapt_general"]["verbose"]):bar.start()
		total = int(self.zap.pscan.records_to_scan)
		while(int(self.zap.pscan.records_to_scan) > 0):
			if(self.args["adapt_general"]["verbose"]):bar.update(int(self.zap.pscan.records_to_scan)/total)
			time.sleep(1)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Pscan done")

	def ascan(self):
		self.printer.aprint("Ascan start")
		self.check()
		scanid = self.zap.ascan.scan(contextid=self.contextid)
		bar = progressbar.ProgressBar(maxval=100, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		if(self.args["adapt_general"]["verbose"]):bar.start()
		while(True):
			scan_progress = int(self.zap.ascan.status(scanid))
			if(self.args["adapt_general"]["verbose"]):bar.update(scan_progress)
			if(scan_progress >= 100):
				break
			time.sleep(2)
		if(self.args["adapt_general"]["verbose"]):bar.finish()
		self.printer.aprint("Ascan done")

def chain_zap_ops(lof):
	for f in lof:
		res = f()
		if(res != "OK"):
			return res
	return res

