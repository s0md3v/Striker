from setuptools import setup, find_packages

# THESE ARE SOME VARIBALES TO BE FILLED BY SOMDEV

details = {"name": "Striker",
           "version": "",
           "brief_description": "",
           "long_description": "",    # you can use github readme.md as it is (markdown format accepted)
           "author_name": "Somdev Sangwan",
           "author_email": "",
           "home_url": "",     # github repo link
           "download_url": "https://github.com/UltimateHackers/Striker/tarball/master",   # repo download link
           "license": "GNU",
           "keywords": "",
           "entry_point": {'console_scripts': ['striker=striker:main']},
           "dependencies": ["requests==2.18.1","mechanize==0.2.5", "bs4==0.0.1"],
           "python_version_supported": ">=2.1, <=2.7",
           "classifiers": [], # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
           "packages": find_packages(exclude=['contrib', 'docs', 'tests*'])
           }

#  setup function



setup(name=details["name"], version=details["version"], description=details['brief_description'],
      long_description=details['long_description'],
        classifiers = details['classifiers'],install_requires=details["dependencies"],
      author=details["author_name"], author_email=details["author_email"], url=details["home_url"], download_url=details["download_url"],
      license=details["license"], python_requires=details["python_version_supported"], packages=details["packages"],
      entry_points=details["entry_point"]
      )

