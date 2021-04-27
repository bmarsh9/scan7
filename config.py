import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    #SERVER_NAME = "localhost"
    APP_NAME = "Scan7"
    APP_SUBTITLE = "Complete Code Scanning"
    CR_YEAR = "2021"

    LOG_TYPE = os.environ.get("LOG_TYPE", "stream")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'newllkjlreagjeraihgeorvhlkenvol3u4og98u4g893u4g0u3409u34add'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    #DISABLE_REGISTRATION = True
    USER_ENABLE_REGISTER = False
    USER_ENABLE_USERNAME  = False
    USER_ALLOW_LOGIN_WITHOUT_CONFIRMED_EMAIL = True
    USER_EMAIL_SENDER_EMAIL = "admin@example.com"
    USER_ENABLE_INVITE_USER = True
    USER_REQUIRE_INVITATION = True

    DEFAULT_EMAIL = os.environ.get("DEFAULT_EMAIL", "admin@example.com")
    DEFAULT_PASSWORD = os.environ.get("DEFAULT_PASSWORD", "admin")

    RESTRICTED_FIELDS = ["password_hash"]

    GIT_KEY_DIR = os.path.join(basedir,"app","keys")
    REPO_CLONE_DIR = os.path.join(basedir,"app","clone_output")

    DEPENDENCY_DIR = os.path.join(basedir,"app","lib","dependency_scan")
    DEPENDENCY_SCRIPT = os.path.join(basedir,"app","lib","dependency_scan","run_dp_check.sh")
    DEPENDENCY_FILE = os.path.join(basedir,"app","lib","dependency_scan","odc-reports","dependency-check-report.csv")

    SECRET_DIR = os.path.join(basedir,"app","lib","gitleaks","results")
    SECRET_SCRIPT = os.path.join(basedir,"app","lib","gitleaks","run_gl_check.sh")
    SECRET_FILE = os.path.join(basedir,"app","lib","gitleaks","results","output.json")

    JOB_DEBUG = True

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'postgresql://db5:db5@localhost/db5'

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'postgresql://db5:db5@postgres_db/db5'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
