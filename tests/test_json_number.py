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

import json
import os
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
for d in ("src", "bin", "lib", "var"):
	sys.path.insert(0, os.path.join(here, "..", d))

reason = ""
try:
	from owasp_suite import json_number
	from welch import welch_ttest
except BaseException as e:   # owasp_suite exits if ADAPT's packages aren't installed
	json_number = None
	reason = "owasp_suite needs ADAPT's venv: " + str(e)


@unittest.skipIf(json_number is None, reason)
class JsonNumberTest(unittest.TestCase):
	def test_finite_values_unchanged(self):
		self.assertEqual(json_number(2.5), 2.5)
		self.assertEqual(json_number(0), 0.0)

	def test_non_finite_values_become_strings(self):
		self.assertEqual(json_number(float("inf")), "inf")
		self.assertEqual(json_number(float("-inf")), "-inf")
		self.assertEqual(json_number(float("nan")), "nan")

	def test_ident_004_misc_is_strict_json(self):
		# Constant but different samples: the t statistic is -inf (#76)
		res = welch_ttest([10.0] * 15, [20.0] * 15)
		misc = {"statistic": json_number(res.statistic), "pvalue": json_number(res.pvalue), "df": json_number(res.df)}
		self.assertEqual(misc["statistic"], "-inf")
		json.dumps(misc, allow_nan=False)   # raises if anything isn't valid JSON


if __name__ == "__main__":
	unittest.main()
