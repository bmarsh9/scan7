from flask import current_app
from flask_script import Command
from app.models import User, Role, Tasks
from app import db
import datetime

class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('Database has been initialized.')

def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_users()
    create_jobs()

def create_users():
    """ Create users """

    default_user = current_app.config.get("DEFAULT_EMAIL","admin@example.com")
    default_password = current_app.config.get("DEFAULT_PASSWORD","admin")
    if not User.query.filter(User.email == default_user).first():
        user = User(
            email=default_user,
            email_confirmed_at=datetime.datetime.utcnow(),
            password=current_app.user_manager.hash_password(default_password),
        )
        user.roles.append(Role(name='Admin'))
        user.roles.append(Role(name='User'))
        db.session.add(user)
        db.session.commit()
    return

def create_jobs():
    tasks = [
        {"name":"run_scancode","module":"run_scancode","description":"Execute vulnerability, license and secret scanning"},
    ]
    for task in tasks:
        if not Tasks.query.filter(Tasks.module == task["module"]).first():
            new_task = Tasks(name=task["name"],module=task["module"],description=task["description"],enabled=False)
            db.session.add(new_task)
            db.session.commit()

    return True
