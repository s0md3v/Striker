import re

from core.utils import var, deJSON, make_list

signatures = var('tech_signatures')

def wappalyzer(response, js, scripts):
	result = []
	headers = response.headers
	source_code = response.text
	if 'Cookie' in headers:
		for app in signatures['apps']:
			if 'cookies' in signatures[app]:
				for pattern in signatures['apps'][app]['cookies']:
					if re.search(deJSON(pattern), headers['Cookie']):
						result.append(app)
						if 'implies' in signatures['apps'][app]:
							for tech in signatures['apps'][app]['implies']:
								result.append(app)
	for app in signatures['apps']:
		if 'headers' in signatures['apps'][app]:
			for header in signatures['apps'][app]['headers']:
				if header in headers:
					if re.search(deJSON(signatures['apps'][app]['headers'][header]), headers[header]):
						result.append(app)
	for app in signatures['apps']:
		if 'html' in signatures['apps'][app]:
			for pattern in make_list(signatures['apps'][app]['html']):
				if re.search(deJSON(pattern), source_code):
					result.append(app)
					if 'implies' in signatures['apps'][app]:
						for tech in signatures['apps'][app]['implies']:
							result.append(app)
	for app in signatures['apps']:
		if 'scripts' in signatures['apps'][app]:
			for pattern in make_list(signatures['apps'][app]['scripts']):
				for script in scripts:
					if re.search(deJSON(pattern), script):
						result.append(app)
						if 'implies' in signatures['apps'][app]:
							for tech in signatures['apps'][app]['implies']:
								result.append(app)
	for app in signatures['apps']:
		if 'js' in signatures['apps'][app]:
			for pattern in make_list(signatures['apps'][app]['js']):
				for j in js:
					if re.search(deJSON(pattern), j):
						result.append(app)
						if 'implies' in signatures['apps'][app]:
							for tech in signatures['apps'][app]['implies']:
								result.append(app)
	return result
