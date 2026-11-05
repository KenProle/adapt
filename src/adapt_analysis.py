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

import json, datetime, csv, os, pathlib, time, tempfile
from dicttoxml import dicttoxml

_PARANOID_VALUE = -1.0
_LOW_VALUE = 0.25
_MEDIUM_VALUE = 0.50
_HIGH_VALUE = 0.75

RISK_CONFIDENCE_VALUES = {
	"paranoid":_PARANOID_VALUE,
	"low":_LOW_VALUE,
	"medium":_MEDIUM_VALUE,
	"high":_HIGH_VALUE,
	"none":0.0
}

def get_val(v):
	return RISK_CONFIDENCE_VALUES.get(v, 1.0)

class report():
	def __init__(self, name, description="", severity="low", request="", confidence=0.0, misc=[], path="", preventions=[], specific_cwe=None, relevant_cwes=[], owasp_association=None):
		if(type(confidence) == str):
			if(confidence == "low"):
				confidence = 0.25
			elif(confidence == "medium"):
				confidence = 0.5
			elif(confidence == "high"): 
				confidence = 0.75
			else:
				confidence = 0.0
		self.confidence = confidence 
		self.name = name 
		# Description is of the vulnerability
		self.description = description
		self.severity = severity 
		self.request = request 
		self.misc = misc
		self.path = path 
		self.preventions = preventions
		if(specific_cwe != None):
			self.cwe_num = int(specific_cwe)
		else:
			self.cwe_num = None
		self.relevant_cwes = relevant_cwes
		self.owasp_association = owasp_association

	def get_low_report(self):
		p = "fail" 
		if(self.severity == "low" or self.severity == "none"):
			p = "pass"
		return {"name":self.name,
			"result":p
		}

	def get_medium_report(self):
		return {
			"name" : self.name,
			"description":self.description,
			"severity":self.severity,
			"confidence":self.confidence	
		}

	def get_high_report(self):
		return {
			"name" : self.name,
			"description": self.description,
			"severity" : self.severity,
			"confidence" : self.confidence,
			"path" : self.path,
			"request" : self.request,
			"cwe_id" : self.cwe_num,
			"preventions" : self.preventions
		}

	def get_full_report(self):
		return {
			"name" : self.name,
			"description": self.description,
			"severity" : self.severity,
			"confidence":self.confidence,
			"path":self.path,
			"request" : self.request,
			"cwe_id":self.cwe_num,
			"preventions": self.preventions,
			"misc" : self.misc
		}

class adapt_analysis():
	def __init__(self, zap_results, owasp_results, args, ssh_logs=None):
		self.args = args
		# (remote_path, local_file) pairs downloaded over SSH
		self.ssh_logs = ssh_logs or []
		self.owasp_results = owasp_results
		self.zap_results = zap_results

		self.analysis_risk_sense = get_val(self.args["adapt_general"]["analysis_risk_sensitivity"])
		self.analysis_conf_sense = get_val(self.args["adapt_general"]["analysis_confidence_sensitivity"])

		self.analysis_detail = self.args["adapt_general"]["analysis_detail"]

		self.output_format = self.__check_output_format(self.args["adapt_general"]["output_format"])
		tm = datetime.datetime.now()
		self.output_file = self.args["adapt_general"]["output_file"]
		self.output_format = self.args["adapt_general"]["output_format"]
		backup_name = "adaptOut_{}_{}{}".format(tm.day, tm.hour, tm.minute)
		if(self.output_file == None):
			self.output_file = "./output/"+backup_name+".{}".format(self.output_format)
		# Fallback JSON file used if the output file cannot be written
		self.backup = "./output/"+backup_name+"_backup.json"
		self.last_resort = os.path.join(tempfile.gettempdir(), backup_name+".json")

		self.ssh_scan_data = self.ssh_scan()

		with open(os.getcwd()+self.args["adapt_general"]["owasp_top10_file"]) as datafile:
			top10_info = json.load(datafile)
		datafile.close()
		self.owasp_top10 = top10_info

		self.final_results = {}
		filtered_final = []

		# filter out those unspecified 
		for i in range(len(zap_results["alerts"])):
			passed_conf = False
			passed_risk = False
			if(get_val(zap_results["alerts"][i]["confidence"].lower()) >= self.analysis_conf_sense):
				passed_conf = True
			if(get_val(zap_results["alerts"][i]["risk"].lower()) >= self.analysis_risk_sense):
				passed_risk = True

			if(passed_conf == True and passed_risk == True):
				temp = zap_results["alerts"][i]
				filtered_final.append(report(
					name=temp["name"],
					description=temp["description"],
					severity=temp["risk"].lower(),
					request=temp["url"],
					confidence=temp["confidence"].lower(),
					misc=[],
					preventions=[temp["solution"]],
					specific_cwe = temp["cweid"],
					relevant_cwes = []
				))
			 
		errors = []
		for i in range(len(owasp_results)):
			# A test that crashed is not a finding: list it separately and
			# regardless of the risk/confidence filters, so it can't be
			# filtered away or reported as a "pass".
			if(owasp_results[i].get("error")):
				errors.append({
					"name":owasp_results[i]["name"],
					"description":owasp_results[i]["basic_description"],
					"misc":owasp_results[i]["misc"]
				})
				continue
			passed_conf = False
			passed_risk = False
			passed_active = False
			if(owasp_results[i]["confidence"] >= self.analysis_conf_sense):
				passed_conf = True
			if(get_val(owasp_results[i]["severity"]) >= self.analysis_risk_sense):
				passed_risk = True

			if(self.args["owasp_general"]["tests_to_run"][owasp_results[i]["name"]] == True):
				passed_active = True

			if(passed_conf == True and passed_risk == True and passed_active == True):
				temp = owasp_results[i]
				filtered_final.append(report(
					name=temp["name"],
					description=temp["basic_description"],
					severity=temp["severity"],
					confidence=temp["confidence"],
					misc=temp["misc"],
					path=temp["path"],
					request=temp["request"],
					preventions=temp["preventions"],
					specific_cwe=temp["cwe_id"],
					relevant_cwes = temp["related_cwes"],
					owasp_association=temp["owasp_association"]
				))

			else:
				print(passed_conf, end=" ")
				print(passed_risk)

		
		# perform any other kind of formatting here
		if(self.analysis_detail == "owasp10"):
			self.final_results["adapt"] = self.__owasp10_owasp(filtered_final)
		elif(self.analysis_detail == "full"):
			self.final_results["adapt"] = self.__full_process_owasp(filtered_final)
		elif(self.analysis_detail == "high"):
			self.final_results["adapt"] = self.__high_process_owasp(filtered_final)
		elif(self.analysis_detail == "medium"):
			self.final_results["adapt"] = self.__med_process_owasp(filtered_final)
		else:
			self.final_results["adapt"] = self.__low_process_owasp(filtered_final)

		if(errors):
			self.final_results["errors"] = errors

		if(self.ssh_scan_data != []):
			self.final_results["ssh_log_data"] = self.ssh_scan_data

		self.final_results["timestamp"] = int(time.time())
		self.final_results = [self.final_results]

	def __check_output_format(self, var):
		if(var == "xml"):
			return "xml"
		elif(var == "stdout"):
			return "stdout"
		else:
			return "json"
		
	def ssh_scan(self):
		if(self.args["ssh_config"]["turned_on"] == False):
			return []
		final = []
		direction = self.args["ssh_config"]["read_direction"]
		try:
			read_amount = int(self.args["ssh_config"]["read_amount"])
		except (ValueError, TypeError, KeyError):
			direction = "full"

		for remote_path, local_file in self.ssh_logs:
			with open(local_file, errors="replace") as f_handle:
				data = f_handle.readlines()
			first = 0
			if(direction == "top"):
				data = data[:max(read_amount, 0)]
			elif(direction == "bottom"):
				first = max(len(data) - max(read_amount, 0), 0)
				data = data[first:]
			for offset, text in enumerate(data):
				for word in self.args["ssh_config"]["keywords"]:
					if(word in text):
						final.append({
							"file":remote_path,
							"line_number":first + offset,
							"value":text
						})

		return final
	def __owasp10_owasp(self, results):
		ret = []

		for item in self.owasp_top10.keys():
			temp = {}
			temp["name"] = self.owasp_top10[item]["name"]
			temp["description"] = self.owasp_top10[item]["description"] 
			temp["possible_solutions"] = self.owasp_top10[item]["preventions"] 
			temp["findings"] = []
			ret.append(temp)

		for vuln in results:
			for item in self.owasp_top10.keys():
				if(vuln.cwe_num in self.owasp_top10[item]["relevant_cwes"]):
					ret[int(item)]["findings"].append(vuln.get_full_report()) 
				elif(vuln.owasp_association == item):
					ret[int(item)]["findings"].append(vuln.get_full_report())
		pops = []
		for item in range(len(ret)):
			if(len(ret[item]["findings"]) == 0):
				pops.append(item)
		
		subtraction = 0
		for item in pops:
			ret.pop(item-subtraction)
			subtraction+=1
		
		return ret
	def __full_process_owasp(self, results):
		x = []
		for i in results:
			x.append(i.get_full_report())
		return x

	def __high_process_owasp(self, results):
		x = []
		for i in results:
			x.append(i.get_high_report())
		return x

	def __med_process_owasp(self, results):
		x = []
		for i in results:
			r = i.get_medium_report()
			found = False
			for j in x:
				if(r["name"] == j["name"] and r["description"] == j["description"] and r["confidence"] <= j["confidence"]):
					found = True
					break
			if(found == False):
				x.append(r)
		return x

	def __low_process_owasp(self, results):
		x = []
		for i in results:
			x.append(i.get_low_report())
		return x

	def get_results(self):
		try:
			pathlib.Path('./output/').mkdir(parents=True, exist_ok=True)
			if(self.output_format == "xml"):
				xml = dicttoxml(self.final_results, attr_type=False)
				with open(self.output_file, "wb") as f:
					f.write(xml)
			else:
				if(self.args["adapt_general"]["append"] == True and os.path.isfile(self.output_file)):
					with open(self.output_file, "r") as f:
						d = json.load(f)
					d += self.final_results
					self.final_results = d
				with open(self.output_file, "w") as f:
					json.dump(self.final_results, f, indent=4)
			print("ADAPT results written to "+self.output_file)
			return
		except Exception as e:
			print("Could not write results to "+self.output_file+": "+str(e))

		# Don't lose a finished scan: fall back to JSON in ./output/, then
		# to the system temp directory.
		for path in (self.backup, self.last_resort):
			try:
				with open(path, "w") as f:
					json.dump(self.final_results, f, indent=4)
				print("ADAPT results written to "+path+" instead")
				return
			except Exception as e:
				print("Could not write results to "+path+": "+str(e))
		raise RuntimeError("ADAPT could not write its results anywhere")


	def __load_cwe(self):
		x = []
		with open(self.cwe_filename) as csvfile:
			reader = csv.reader(csvfile, delimiter=',', quotechar='"')
			for row in reader:
				x.append(row)
		ret = []
		for i in range(1, len(x)):
			r = {}
			for j in range(len(x[0])):
				r[x[0][j]] = x[i][j]
			ret.append(r)

		return ret
