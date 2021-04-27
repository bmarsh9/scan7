import sys
sys.path.append("../../")

from app import create_app
from flask import current_app
import os

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
from app.models import *

def validate():
    with app.app_context():
        print(Repository.query.all())
        print(RepositoryScan.query.all())
        print(File.query.all())

def validate_rel():
    with app.app_context():
      for repo in Repository.query.all():
        scan = repo.scans.first()
        files = scan.files.all()
        for file in files:
            pkgs = file.packages.all()
            for pkg in pkgs:
                for dep in pkg.dependencies.all():
                    print(dep.purl)
def delete_data():
    with app.app_context():
        File.query.delete()
        RepositoryScan.query.delete()
        Repository.query.delete()



validate()
validate_rel()
#delete_data()

