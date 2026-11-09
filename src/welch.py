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

# Welch's two-sample t-test (unequal variances, two-sided), the one piece of
# scipy ADAPT used: scipy.stats.ttest_ind(a, b, equal_var=False).
#
# The p-value is the two-sided tail of Student's t distribution, computed with
# the regularized incomplete beta function:
#   p = I_x(df/2, 1/2)  with  x = df / (df + t^2)
# I_x(a, b) is evaluated with its standard continued fraction (modified Lentz
# method), using the symmetry I_x(a, b) = 1 - I_(1-x)(b, a) where that
# converges faster. As scipy does, the result is NaN when either sample has
# fewer than two values or both have zero variance.

import math
from collections import namedtuple

WelchResult = namedtuple("WelchResult", ["statistic", "pvalue", "df"])

_EPS = 1e-16
_TINY = 1e-300
_MAX_ITER = 10000


def _beta_cf(a, b, x):
	"""Continued fraction for the incomplete beta function (Lentz)."""
	qab, qap, qam = a + b, a + 1.0, a - 1.0
	c = 1.0
	d = 1.0 - qab * x / qap
	d = 1.0 / (d if abs(d) > _TINY else _TINY)
	h = d
	for m in range(1, _MAX_ITER + 1):
		m2 = 2 * m
		# even step
		aa = m * (b - m) * x / ((qam + m2) * (a + m2))
		d = 1.0 + aa * d
		d = 1.0 / (d if abs(d) > _TINY else _TINY)
		c = 1.0 + aa / c
		c = c if abs(c) > _TINY else _TINY
		h *= d * c
		# odd step
		aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
		d = 1.0 + aa * d
		d = 1.0 / (d if abs(d) > _TINY else _TINY)
		c = 1.0 + aa / c
		c = c if abs(c) > _TINY else _TINY
		delta = d * c
		h *= delta
		if abs(delta - 1.0) < _EPS:
			return h
	raise ArithmeticError("incomplete beta continued fraction did not converge")


def betainc(a, b, x):
	"""Regularized incomplete beta function I_x(a, b) for a, b > 0, 0 <= x <= 1."""
	if math.isnan(x) or math.isnan(a) or math.isnan(b):
		return math.nan
	if x <= 0.0:
		return 0.0
	if x >= 1.0:
		return 1.0
	log_front = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
		+ a * math.log(x) + b * math.log1p(-x))
	if x < (a + 1.0) / (a + b + 2.0):
		return math.exp(log_front) * _beta_cf(a, b, x) / a
	return 1.0 - math.exp(log_front) * _beta_cf(b, a, 1.0 - x) / b


def _mean_var(values):
	n = len(values)
	mean = math.fsum(values) / n
	var = math.fsum((v - mean) ** 2 for v in values) / (n - 1)
	return mean, var


def welch_ttest(a, b):
	"""Welch's t-test for samples a and b: WelchResult(statistic, pvalue, df).

	Edge cases follow scipy: an empty sample gives NaN for everything; a
	sample with one value gives NaN statistic and p-value; when neither
	sample varies, different means give statistic +/-inf and p-value 0, and
	equal means give NaN. scipy reports df as 1 wherever it would be
	undefined, and so does this.
	"""
	a = [float(v) for v in a]
	b = [float(v) for v in b]
	n1, n2 = len(a), len(b)
	if n1 == 0 or n2 == 0:
		return WelchResult(math.nan, math.nan, math.nan)
	if n1 < 2 or n2 < 2:
		return WelchResult(math.nan, math.nan, 1.0)
	m1, v1 = _mean_var(a)
	m2, v2 = _mean_var(b)
	s1, s2 = v1 / n1, v2 / n2
	se2 = s1 + s2
	diff = m1 - m2
	if se2 == 0.0:
		if diff == 0.0:
			return WelchResult(math.nan, math.nan, 1.0)
		return WelchResult(math.copysign(math.inf, diff), 0.0, 1.0)
	statistic = diff / math.sqrt(se2)
	df = se2 * se2 / (s1 * s1 / (n1 - 1) + s2 * s2 / (n2 - 1))
	t2 = statistic * statistic
	pvalue = betainc(df / 2.0, 0.5, df / (df + t2))
	return WelchResult(statistic, min(pvalue, 1.0), df)
