import sys

sys.path.append("..")

from app import create_app
from flask import current_app
import os
import subprocess
import csv
import json

app = create_app(os.getenv('FLASK_CONFIG') or 'default')

with app.app_context():
    #config = current_app.config
    script_file = current_app.config["DEPENDENCY_SCRIPT"]
    output_file = current_app.config["DEPENDENCY_FILE"]
    output_dir = current_app.config["DEPENDENCY_DIR"]
    repo_dir = os.path.join(current_app.config["REPO_CLONE_DIR"],"test")
    p = subprocess.Popen(["/bin/bash",script_file,output_dir,repo_dir],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.communicate()

    indexed_fields = {
        "description":"description", "license":"license","identifiers":"identifiers",
        "cpe":"cpe", "cve":"cve", "cwe":"cwe", "vulnerability":"vulnerability",
        "source":"source", "cvssv2_severity":"cvssv2_severity", "cvssv2_score":"cvssv2_score",
        "cvssv2":"cvssv2", "cvssv3_baseseverity":"cvssv3_base_severity", "cvssv3_basescore":"cvssv3_base_score",
        "cvssv3":"cvssv3", "cpe confidence":"cpe_confidence", "evidence count":"evidence_count"
    }

    data = []
    with open(output_file) as f:
        csv_reader = csv.DictReader(f)
        line_count = 0
        for row in csv_reader[1:]:
            temp = {}
            for key,value in row.items():
                key = key.lower()
                if key in indexed_fields:
                    temp[indexed_fields[key]] = value
            if temp:
                data.append(temp)
        line_count += 1
    print(json.dumps(data,indent=4))
