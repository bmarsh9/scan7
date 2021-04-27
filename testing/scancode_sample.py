import os
import json
from scancode import cli

def run(path):
    kw = {
      "reindex_licenses": True, "list_packages": True, "copyright": True, "license": True, "package": True, "email": True, "url": True, "info": True,
      "classify": False, "facet": None, "ignore": (), "include": (), "max_email": 50, "generated": False, "license_score": 0, "license_text": False,
      "license_text_diagnostics": False, "license_url_template": "https://scancode-licensedb.aboutcode.org/{}",
      "max_url": 50, "consolidate": False, "filter_clues": False, "is_license_text": False, "license_clarity_score": False, "license_policy": None,
      "mark_source": False, "summary": False, "summary_by_facet": False, "summary_with_details": False, "summary_key_files": False,
      "ignore_copyright_holder": (), "ignore_author": (), "only_findings": False, "csv": None, "html": None, "html_app": None, "output_json": True,
      "output_json_lines": None, "spdx_rdf": None, "spdx_tv": None, "custom_output": None, "custom_template": None
    }
    #path=["/api-scan/scancode"]

    success, _results = cli.run_scan(
        path,
        quiet=False,
        license=True,
        copyright=True,
        url=True,
        package=True,
        info=True,
        email=True,
        classify=True,
        list_packages=True,
        return_results=True
        #kwargs=kw,
    )
    return success, _results

success, _results = run("/api-scan/scancode")
if success:
    file_key_dict = {}
    for file in _results["files"]:
        for key,value in file.items():
#            if key in file_keys:
                print(key,value)

