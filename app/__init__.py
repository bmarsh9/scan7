from flask import Flask,request,render_template,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager
from flask_migrate import Migrate, MigrateCommand
from app.utils.flask_logs import LogSetup
from config import config
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
logs = LogSetup()
migrate = Migrate()

import app.jobs as schjobs

def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)
    logs.init_app(app)

    from app.models import User,UserInvitation
    app.user_manager = UserManager(app, db, User,UserInvitationClass=UserInvitation)
    app.db_manager = app.user_manager.db_manager

    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from app.api_v1 import api as api_v1_blueprint
    app.register_blueprint(api_v1_blueprint, url_prefix='/api/v1')

    # Add all models
    all_models = {}
    classes, models, table_names = [], [], []
    for clazz in db.Model._decl_class_registry.values():
        try:
            table_names.append(clazz.__tablename__)
            classes.append(clazz)
        except:
            pass
    for table in db.metadata.tables.items():
        if table[0] in table_names:
            all_models[table[0]] = classes[table_names.index(table[0])]
            models.append(classes[table_names.index(table[0])])
    app.models = all_models

    # Setup Flask-Migrate
    migrate.init_app(app, db)

    from app.models import Tasks

    def background_daemon():
        with app.app_context(),app.test_request_context():
            for task in Tasks().ready_to_run():
                if app.config["JOB_DEBUG"]:
                    task.add_log("Executing job: {}".format(task.name),namespace="jobs",meta={"module":task.module})
                task.was_executed()
                args = task.args or {}
                result = getattr(schjobs,task.module)(task,**args)
                if result:
                    task.healthy = True
                else:
                    task.healthy = False
                db.session.commit()

    scheduler = BackgroundScheduler()
    scheduler.add_job(background_daemon, 'interval', seconds=15, misfire_grace_time=3600)
    scheduler.start()

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"),404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template("errors/500.html"),500

    @app.errorhandler(401)
    def unauthorized(e):
        if 'Authorization' in request.headers:
            return jsonify({"message":"unauthorized"}),401
        return "bad"

    @app.errorhandler(400)
    def malformed(e):
        if 'Authorization' in request.headers:
            return jsonify({"message":"malformed request"}),400
        return "bad"

    @app.errorhandler(403)
    def forbidden(e):
        if 'Authorization' in request.headers:
            return jsonify({"message":"forbidden"}),403
        return "bad"

    '''
    @app.before_request
    def before_request():
        pass
    '''

    return app
