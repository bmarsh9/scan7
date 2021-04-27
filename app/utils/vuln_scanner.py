from flask import current_app
import subprocess
import os
import csv

class VulnScanner():
    def __init__(self,repository_path):
        self.script_file = current_app.config["DEPENDENCY_SCRIPT"]
        self.output_file = current_app.config["DEPENDENCY_FILE"]
        self.output_dir = current_app.config["DEPENDENCY_DIR"]
        self.repository_path = repository_path

    def scan(self):
        scan_repo = subprocess.Popen(["/bin/bash",self.script_file,self.output_dir,self.repository_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        scan_repo.communicate()

        indexed_fields = {
            "dependencyname":"name","description":"description", "license":"license","identifiers":"identifiers",
            "cpe":"cpe", "cve":"cve", "cwe":"cwe", "vulnerability":"vulnerability",
            "source":"source", "cvssv2_severity":"cvssv2_severity", "cvssv2_score":"cvssv2_score",
            "cvssv2":"cvssv2", "cvssv3_baseseverity":"cvssv3_base_severity", "cvssv3_basescore":"cvssv3_base_score",
            "cvssv3":"cvssv3", "cpe confidence":"cpe_confidence", "evidence count":"evidence_count"
        }

        data = []
        with open(self.output_file) as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                temp = {}
                for key,value in row.items():
                    key = key.lower()
                    if key in indexed_fields:
                        temp[indexed_fields[key]] = value
                if temp:
                    data.append(temp)
        return data
