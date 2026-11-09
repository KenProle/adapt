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

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from welch import betainc, welch_ttest


class WelchTTestTest(unittest.TestCase):
	# (a, b, statistic, pvalue, df) from scipy 1.18.1:
	# scipy.stats.ttest_ind(a, b, equal_var=False)
	SCIPY = {
		"rtt_like": ([101.2, 99.8, 100.5, 102.1, 98.9, 100.0, 101.7, 99.3], [106.4, 104.9, 107.2, 105.5, 106.0, 108.1, 104.7, 105.9], -9.881615243181866, 1.0826325077792966e-07, 13.99966166691141),
		"unequal_sizes_and_spread": ([0.91, 0.93, 0.88, 0.95], [0.72, 0.99, 0.45, 0.81, 0.63, 0.97, 0.58], 2.3480834064209413, 0.05425760683531898, 6.45323903753747),
		"no_difference": ([1.0, 2.0, 3.0, 4.0], [1.5, 2.5, 3.5, 2.5], 0.0, 1.0, 5.068965517241378),
		"small_df": ([1.0, 3.0], [10.0, 10.5, 11.0, 9.5, 10.2], -7.993598040728599, 0.062474748263681296, 1.128013656301058),
		"tiny_p": ([0.0, 0.1, -0.1, 0.05], [50.0, 50.2, 49.9, 50.1], -646.5428261816444, 5.783888978445858e-14, 5.203278688524548),
	}

	def test_matches_scipy(self):
		for name, (a, b, statistic, pvalue, df) in self.SCIPY.items():
			with self.subTest(name):
				r = welch_ttest(a, b)
				self.assertTrue(math.isclose(r.statistic, statistic, rel_tol=1e-9, abs_tol=1e-12))
				self.assertTrue(math.isclose(r.pvalue, pvalue, rel_tol=1e-9))
				self.assertTrue(math.isclose(r.df, df, rel_tol=1e-9))

	def test_fields_by_name(self):
		r = welch_ttest([1.0, 2.0, 3.0], [4.0, 5.0, 7.0])
		self.assertEqual(r, (r.statistic, r.pvalue, r.df))

	def test_no_variance_different_means(self):
		self.assertEqual(welch_ttest([1, 1, 1], [2, 2, 2]), (-math.inf, 0.0, 1.0))
		self.assertEqual(welch_ttest([2, 2, 2], [1, 1, 1]), (math.inf, 0.0, 1.0))

	def test_no_variance_same_means(self):
		r = welch_ttest([1, 1, 1], [1, 1, 1])
		self.assertTrue(math.isnan(r.statistic) and math.isnan(r.pvalue))
		self.assertEqual(r.df, 1.0)

	def test_one_value(self):
		r = welch_ttest([5], [1, 2, 3])
		self.assertTrue(math.isnan(r.statistic) and math.isnan(r.pvalue))
		self.assertEqual(r.df, 1.0)

	def test_empty(self):
		self.assertTrue(all(math.isnan(x) for x in welch_ttest([1, 2, 3], [])))

	def test_symmetry(self):
		a, b = [3.1, 2.9, 3.4, 3.0], [3.6, 3.9, 3.5, 4.1, 3.8]
		r1, r2 = welch_ttest(a, b), welch_ttest(b, a)
		self.assertEqual(r1.statistic, -r2.statistic)
		self.assertEqual(r1.pvalue, r2.pvalue)

	def test_betainc_known_values(self):
		# I_x(a, 1) = x^a and I_x(1, b) = 1 - (1 - x)^b
		for x in (0.01, 0.3, 0.5, 0.9, 0.999):
			self.assertTrue(math.isclose(betainc(2.5, 1.0, x), x ** 2.5, rel_tol=1e-12))
			self.assertTrue(math.isclose(betainc(1.0, 3.0, x), 1 - (1 - x) ** 3, rel_tol=1e-12))
		self.assertEqual(betainc(2.0, 0.5, 0.0), 0.0)
		self.assertEqual(betainc(2.0, 0.5, 1.0), 1.0)
		# I_x(a, b) + I_(1-x)(b, a) = 1
		self.assertTrue(math.isclose(betainc(3.7, 0.5, 0.42) + betainc(0.5, 3.7, 0.58), 1.0, rel_tol=1e-12))


if __name__ == "__main__":
	unittest.main()
