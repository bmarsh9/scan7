import sys
sys.path.append("..")

from app import create_app
from flask import current_app
import os

app = create_app(os.getenv('FLASK_CONFIG') or 'default')

with app.app_context():
    #config = current_app.config
    pass
