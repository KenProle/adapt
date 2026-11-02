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

# File: insecure_bank_login.py
# ADAPT

import requests
from pprint import pprint
import time, socket, struct

# Authentication script for Insecure Bank. See login_format.py for the
# required function name, parameters and return value.
#
# Insecure Bank uses a plain form POST with no csrf token. A successful login
# redirects to the app root, a failed one redirects back to the login page
# with ?authenticationFailure=true

# Insecure Bank runs on the Windows host, which WSL can't reach as localhost.
# The Windows host is WSL's default gateway, which can change when WSL
# restarts, so look it up instead of hard coding it.
def windows_host():
	try:
		with open("/proc/net/route") as f:
			for line in f.readlines()[1:]:
				fields = line.split()
				if(fields[1] == "00000000"):
					return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
	except OSError:
		pass
	return "localhost"

# This is the login url we are going to post to
login_url = "http://"+windows_host()+":8080/insecure-bank/login"

def service_auth(username, password):

	# Setting up the post data information
	payload = {"username":username, "password":password}

	# Create a requests session so the session cookie is kept between requests
	client = requests.session()

	# GET the login page first to get a session cookie, like a browser would
	client.get(login_url)

	# Initialize timer for login
	rtt = time.time()

	# Make login POST request, following the redirect so responseBody holds
	# the page the user lands on
	post = client.post(login_url, data=payload, allow_redirects=True)

	# Round trip time in milliseconds
	rtt = (time.time()-rtt)*1000

	# The login POST itself is the first response in the redirect chain
	login_resp = post.history[0] if post.history else post

	# Failed logins are sent back to the login page
	successful = "authenticationFailure" not in post.url and not post.url.rstrip("/").endswith("/login")

	# Make sure the request values are not empty and return strings
	request_headers = ""
	for key,val in login_resp.request.headers.items():
		request_headers += key+": "+val+"\r\n"

	request_body = ""
	if(login_resp.request.body != None):
		request_body = login_resp.request.body

	# Make sure the response headers are one string
	response_headers = ""
	for key,val in login_resp.headers.items():
		response_headers += key+": "+val+"\r\n"

	# Return dictionary
	return {
		"responseHeader":response_headers,
		"requestHeader":request_headers,
		"requestBody":request_body,
		"successful":successful,
		"cookies":client.cookies.get_dict(),
		"rtt":rtt,
		"responseBody":post.text
	}

if(__name__ == "__main__"):
	pprint(service_auth("john", "test")["successful"])
	pprint(service_auth("john", "wrong")["successful"])
	pprint(service_auth("john", "test")["cookies"])
