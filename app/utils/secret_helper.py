from flask import current_app
import re

class SecretScanner():
    def __init__(self):
        pass

    def get_patterns(self):
        # db call
        return ["(?i)\baws\b"]

    def scan_file(self,location):
            patterns = self.get_patterns()
            f = open(location)
            try:
                for i, line in enumerate(f):
                    for pattern in patterns:
                        p = re.compile(pattern)
                        for match in re.finditer(p, line):
                            print("MATCH")
            except UnicodeDecodeError:
                pass

