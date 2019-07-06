import re
import concurrent.futures
from urllib.parse import urlparse

from core.colors import run
from core.utils import getUrl, getParams, js_extractor, script_extractor, handle_anchor
from core.requester import requester
from core.zetanize import zetanize

from modules.retirejs import retirejs
from modules.wappalyzer import wappalyzer


def is_link(url, processed):
    """
    Determine whether or not a link should be crawled
    A url should not be crawled if it
        - Is a file
        - Has already been crawled
    Args:
        url: str Url to be processed
        processed: list[str] List of urls that have already been crawled
    Returns:
        bool If `url` should be crawled
    """
    if url not in processed:
        if url.startswith('#') or url.startswith('javascript:'):
            return False
        is_file = url.endswith(['pdf', 'jpg', 'jpeg', 'png', 'docx', 'csv', 'xls'])
        if is_file:
            return False
        return True
    return False


def photon(seedUrl):
    forms = []  # web forms
    processed = set()  # urls that have been crawled
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + '://' + host  # join scheme and host to make the root url
    storage.add(seedUrl)  # add the url to storage
    checkedScripts = set()
    all_techs = []
    all_outdated_js = []

    def rec(target):
        processed.add(target)
        urlPrint = (target + (' ' * 60))[:60]
        print ('%s Parsing %-40s' % (run, urlPrint), end='\r')
        url = getUrl(target, True)
        params = getParams(target, '', True)
        if '=' in target:  # if there's a = in the url, there should be GET parameters
            inps = []
            for name, value in params.items():
                inps.append({'name': name, 'value': value})
            forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
        raw_response = requester(url, params, True)
        response = raw_response.text
        js = js_extractor(response)
        scripts = script_extractor(response)
        for each in retirejs(url, response, checkedScripts):
            all_outdated_js.append(each)
        all_techs.extend(wappalyzer(raw_response, js, scripts))
        parsed_response = zetanize(response)
        forms.append(parsed_response)
        matches = re.finditer(r'<[aA][^>]*?(?:href|HREF)=[\'"`]?([^\s>]*?)[\'"`]?>', response)
        for link in matches:  # iterate over the matches
            # remove everything after a "#" to deal with in-page anchors
            this_url = handle_anchor(target, link.group(1))
            if is_link(this_url, processed):
                if urlparse(this_url).netloc == host:
                    storage.add(this_url.split('#')[0])
    for x in range(2):
        urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
        threadpool = concurrent.futures.ThreadPoolExecutor(
            max_workers=10)
        futures = (threadpool.submit(rec, url) for url in urls)
        for i in concurrent.futures.as_completed(futures):
            pass
    return [forms, processed, set(all_techs), all_outdated_js]
