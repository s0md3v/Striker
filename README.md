<h1 align="center">
  <br>
  <a href="https://github.com/s0md3v/Striker"><img src="https://i.ibb.co/txcs4JL/striker.png" alt="Striker"></a>
  <br>
  Striker
  <br>
</h1>

<h4 align="center">Recon & Vulnerability Scanning Suite</h4>

<p align="center">
  <a href="https://github.com/s0md3v/Striker/releases">
    <img src="https://img.shields.io/github/release/s0md3v/Striker.svg">
  </a>
  <a href="https://travis-ci.com/s0md3v/Striker">
    <img src="https://img.shields.io/travis/com/s0md3v/Striker.svg">
  </a>
  <a href="https://github.com/s0md3v/Striker/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/s0md3v/Striker.svg">
  </a>
</p>

### Important Notice
Striker 2.0 is still in prototype phase, which means it's not intended to be used by regular users. It has been made public for contrbutions to make the development faster.\
**Usage:** `python3 striker.py example.com`

### Workflow
##### Phase 1: Attack Surface Discovery
This phase includes finding subdomains of the user specified domain, filtering alive hosts as well scanning of 1000 most common TCP ports.
##### Phase 2: Sweeping
Mass scanning of misconfigured HTTP response headers, croassdomain.xml as well as checks for some sensitive files is done in this phase.
##### Phase 3: Agressive Information Gathering
This phase is dedicated to data gathering by crawling the subdomains. The gathered data is used to find outdated JS libraries, detect CMS and technologies in use.\
HTML forms that are tested in later phases for vulnerability detection are also collected during this crawling.
##### Phase 4: Vulnerability Scanning
[This phase is under development]

### Credits
`/db/outdated_js.json` is taken from [retire.js](https://github.com/RetireJS/retire.js).\
`/db/tech_signatures.json` is taken from [Wappalyzer](https://github.com/AliasIO/Wappalyzer).\
`/db/waf_signatures.json` is extracted (and converted to JSON) from [sqlmap](https://github.com/sqlmapproject/sqlmap)'s WAF detection modules.\
`/modules/retirejs.py` is a modified version of [retirejslib](https://github.com/FallibleInc/retirejslib).\
`
