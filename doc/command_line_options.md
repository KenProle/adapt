# ADAPT command line options


--target <url>: Set the target URL. This does not change `context` in adapt.config, which decides what ZAP spiders and scans, so keep the two in step.
--verbose : Turns on progress logging for this run, even if `adapt_verbose = off` in adapt.config.
--output <file.json|file.xml> : Write results to this file, replacing it. The extension selects the format.
--append <file.json> : Append results to this JSON file. Can't be combined with --output.
--risk <[low, medium, high, paranoid]> : Specify how sensitive the results will be to discovered risks. 
--conf <[low, medium, high, paranoid]> : Specify how sensitive the results will be in regards to confidence levels 
--detail <[low, medium, high, full, owasp10]> : Specify how detailed or included details are put into the final report. 
	low : Functional pass/fail depending on risk/conf values 
	medium : Basic description of an ecountered problem, and how severe it may be. 
	high : Some more information with regards to links/directories/requests and possible tips about prevention 
	full : Even more information with regards to misc information that may have been scraped. 
	owasp10 : An output method that reports only the vulnerabilities in regards to the owasp top 10. (report detail is otherwise full) 
-h, --help : Show help

Run as `python3 adapt.py ...` from the repo root; it re-runs itself under `.venv` automatically. The options above override the matching settings in `adapt.config` (except as noted for --target).
