from flask import current_app
import subprocess
import os
import json

class SecretScanner():
    def __init__(self,repository_path):
        self.script_file = current_app.config["SECRET_SCRIPT"]
        self.output_file = current_app.config["SECRET_FILE"]
        self.output_dir = current_app.config["SECRET_DIR"]
        self.repository_path = repository_path

    def scan(self):
        scan_repo = subprocess.Popen(["/bin/bash",self.script_file,self.output_dir,self.repository_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        scan_repo.communicate()

        indexed_fields = {
            "line":"line","lineNumber":"line_number","offender":"offender",
            "commit":"commit","rule":"rule","commitMessage":"commit_message",
            "author":"author","email":"email","file":"path","tags":"tags",
        }

        data = []
        with open(self.output_file) as f:
            results = json.loads(f.read())
            if results:
                for secret in results:
                    temp = {}
                    for key,value in secret.items():
                        key = key.lower()
                        if key in indexed_fields:
                            if key == "file": #get filename
                                temp["name"] = os.path.basename(value)
                            temp[indexed_fields[key]] = value.lower()
                    if temp:
                        data.append(temp)
        return data
