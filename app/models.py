from flask import current_app
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import func,and_,or_
from sqlalchemy.orm import validates
from flask_user import UserMixin
from app.utils.mixin_models import LogMixin,DateMixin
from datetime import datetime
from app.utils.misc import generate_uuid
from app import db
import tldextract
import subprocess
from git import Repo
from git import Git
import arrow
import shutil
import os

class GitKey(db.Model,DateMixin):
    __tablename__ = 'git_key'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String())
    file_id = db.Column(db.String())
    repositories = db.relationship('Repository', backref='key')
    last_used = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def add(self,name,key):
        uuid = generate_uuid()
        storage_dir = current_app.config["GIT_KEY_DIR"]
        abs_path = os.path.join(storage_dir,uuid)
        self.write_key(abs_path,key)
        new_key = GitKey(name=name,file_id=uuid)
        db.session.add(new_key)
        db.session.commit()
        return True

    def write_key(self,abs_path,key):
        with open(abs_path,"w+") as file:
            file.write(key)
        os.chmod(abs_path, 0o600)
        r = subprocess.run(["dos2unix","-q",abs_path])
        if r.returncode == 0:
            return True
        return False

    def read_key(self):
        return open(self.get_key_path()).read()

    def get_key_path(self):
        storage_dir = current_app.config["GIT_KEY_DIR"]
        abs_path = os.path.join(storage_dir,self.file_id)
        return abs_path

#------------- File Models -------------
class Repository(db.Model,DateMixin):
    __tablename__ = 'repository'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(),nullable=False)
    enabled = db.Column(db.Boolean,default=True)
    branch = db.Column(db.String(),nullable=False)
    type = db.Column(db.String(),nullable=False) #gitlab,github,etc.
    url = db.Column(db.String(),nullable=False)
    is_private = db.Column(db.Boolean,nullable=False)
    git_key = db.Column(db.Integer, db.ForeignKey('git_key.id'))
    scans = db.relationship('RepositoryScan', backref='repository', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def get_last_scan(self):
        return self.scans.order_by(RepositoryScan.id.desc()).first()

    def clean_clone_dir(self):
        path = self.get_clone_dir()
        if os.path.exists(path):
            shutil.rmtree(path)
        return True

    def get_key_path(self):
        if self.key:
            return self.key.get_key_path()
        return None

    def get_clone_dir(self):
        return os.path.join(current_app.config["REPO_CLONE_DIR"],str(self.id))

    def clone(self,check_host=True,clean=True):
        if clean:
            self.clean_clone_dir()
        env_dict = {}
        if self.git_key:
            if check_host:
                check_host = "yes"
            else:
                check_host = "no"
            git_ssh_cmd = 'ssh -oStrictHostKeyChecking={} -i {}'.format(check_host,self.get_key_path())
            env_dict = {"GIT_SSH_COMMAND": git_ssh_cmd}
        else:
            git_ssh_cmd = 'ssh'
            env_dict = {"GIT_SSH_COMMAND": git_ssh_cmd}
        result = Repo.clone_from(self.url, self.get_clone_dir(), env=env_dict)
        return True

    def get_branches(self):
        if self.branch:
            return self.branch.split(",")
        return []

    def generate_scan_name(self):
        return "{}_{}".format(self.name,generate_uuid(length=6))

    def create_scan_object(self):
        scan = RepositoryScan(name=self.generate_scan_name())
        self.scans.append(scan)
        db.session.commit()
        return scan

    def get_feather_icon(self):
        if self.type == "github":
            return "github"
        elif self.type == "gitlab":
            return "gitlab"
        else:
            return "coffee"

    def update_key_last_used(self):
        if self.key:
            self.key.last_used = arrow.utcnow().datetime
            db.session.commit()
        return True

    @validates("name","type","url","git_key","is_private")
    def validate_fields(self,key,value):
        if key == "type":
            value = value.lower()
            if value not in ["github","gitlab","bitbucket"]:
                raise ValueError("Invalid repository type")
        elif key == "name":
            value = value.lower()
            if Repository.query.filter(Repository.name == value).first():
                raise ValueError("Duplicate repository name")
        elif key == "git_key":
            if value:
                if not GitKey.query.get(int(value)):
                    raise ValueError("Git key does not exist.")
        elif key == "is_private":
            if value == "1":
                value = True
            elif value == "0":
                value = False
        elif key == "url":
            if "@" not in value and "https" not in value:
                raise ValueError("Invalid format of repository url")
        return value

class RepositoryScan(db.Model,DateMixin):
    __tablename__ = 'repository_scan'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(),nullable=False)
    status = db.Column(db.String(),default="new")
    repository_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=False)
    files = db.relationship('File', backref='scan', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def set_status(self,status):
        self.status = status.lower()
        db.session.commit()
        return True

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    path = db.Column(db.String())
    type = db.Column(db.String())
    name = db.Column(db.String(),nullable=False)
    base_name = db.Column(db.String())
    extension = db.Column(db.String())
    size = db.Column(db.Integer)
    date = db.Column(db.String())
    sha1 = db.Column(db.String())
    md5 = db.Column(db.String())
    sha256 = db.Column(db.String())
    mime_type = db.Column(db.String())
    file_type = db.Column(db.String())
    programming_language = db.Column(db.String()) #unsure of the type
    is_binary = db.Column(db.Boolean)
    is_text = db.Column(db.Boolean)
    is_archive = db.Column(db.Boolean)
    is_media = db.Column(db.Boolean)
    is_source = db.Column(db.Boolean)
    is_script = db.Column(db.Boolean)
    percentage_of_license_text = db.Column(db.Integer)
    is_legal = db.Column(db.Boolean)
    is_manifest = db.Column(db.Boolean)
    is_readme = db.Column(db.Boolean)
    is_top_level = db.Column(db.Boolean)
    is_key_file = db.Column(db.Boolean)
    files_count = db.Column(db.Integer)
    dirs_count = db.Column(db.Integer)
    size_count = db.Column(db.Integer)
    extra = db.Column(db.JSON(),default="[]")
    #eventually include plugin to look for secrets and that would be another relationship
    scan_id = db.Column(db.Integer, db.ForeignKey('repository_scan.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())

    secrets = db.relationship('FileSecret', backref='file', lazy='dynamic')
    vulnerabilities = db.relationship('FileVuln', backref='file', lazy='dynamic')
    licenses = db.relationship('FileLicense', backref='file', lazy='dynamic')
    license_expressions = db.relationship('FileLicenseExpression', backref='file', lazy='dynamic')
    copyrights = db.relationship('FileCopyright', backref='file', lazy='dynamic')
    holders = db.relationship('FileHolder', backref='file', lazy='dynamic')
    authors = db.relationship('FileAuthor', backref='file', lazy='dynamic')
    packages = db.relationship('FilePackage', backref='file', lazy='dynamic')
    emails = db.relationship('FileEmail', backref='file', lazy='dynamic')
    urls = db.relationship('FileUrl', backref='file', lazy='dynamic')
    scan_errors = db.relationship('FileScanError', backref='file', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def add_vulnerability(self,vuln):
        name = vuln.get("name")
        if not name:
            return False
        file_found = File.query.filter(File.name == name.lower()).first()
        if file_found:
            file_found.vulnerabilities.append(FileVuln(**vuln))
            db.session.commit()
            return True
        return False

    def add_secret(self,secret):
        name = secret.get("name")
        if not name:
            return False
        file_found = File.query.filter(File.name == name.lower()).first()
        if file_found:
            file_found.secrets.append(FileSecret(**secret))
            db.session.commit()
            return True
        return False

class FileSecret(db.Model):
    __tablename__ = 'file_secret'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String())
    status = db.Column(db.String(),default="unconfirmed") #unconfirmed, pending, confirmed, false_positive
    line = db.Column(db.String())
    line_number = db.Column(db.String())
    offender = db.Column(db.String())
    commit = db.Column(db.String())
    rule = db.Column(db.String())
    commit_message = db.Column(db.String())
    author = db.Column(db.String())
    email = db.Column(db.String())
    path = db.Column(db.String())
    tags = db.Column(db.String()) # TODO add table for secret tags
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileVuln(db.Model):
    __tablename__ = 'file_vuln'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String())
    description = db.Column(db.String())
    license = db.Column(db.String())
    identifiers = db.Column(db.String())
    cpe = db.Column(db.String())
    cve = db.Column(db.String())
    cwe = db.Column(db.String())
    vulnerability = db.Column(db.String())
    source = db.Column(db.String())
    cvssv2_severity = db.Column(db.String())
    cvssv2_score = db.Column(db.Float)
    cvssv2 = db.Column(db.String())
    cvssv3_base_severity = db.Column(db.String())
    cvssv3_base_score = db.Column(db.Float)
    cvssv3 = db.Column(db.String())
    cpe_confidence = db.Column(db.String())
    evidence_count = db.Column(db.Float)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileLicense(db.Model):
    __tablename__ = 'file_license'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    key = db.Column(db.String())
    score = db.Column(db.Integer)
    name = db.Column(db.String())
    short_name = db.Column(db.String())
    category = db.Column(db.String())
    is_exception = db.Column(db.Boolean)
    owner = db.Column(db.String())
    homepage_url = db.Column(db.String())
    text_url = db.Column(db.String())
    reference_url = db.Column(db.String())
    scancode_text_url = db.Column(db.String())
    scancode_data_url = db.Column(db.String())
    spdx_license_key = db.Column(db.String())
    spdx_url = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    matched_rule = db.Column(db.JSON(),default="[]")
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileLicenseExpression(db.Model):
    __tablename__ = 'file_license_expression'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    value = db.Column(db.String())
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileCopyright(db.Model):
    __tablename__ = 'file_copyright'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    value = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileHolder(db.Model):
    __tablename__ = 'file_holder'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    value = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)    
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileAuthor(db.Model):
    __tablename__ = 'file_author'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    value = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)    
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FilePackage(db.Model):
    __tablename__ = 'file_package'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    type = db.Column(db.String())
    namespace = db.Column(db.String())
    name = db.Column(db.String())
    version = db.Column(db.String())
    qualifiers = db.Column(db.JSON(),default="[]")
    subpath = db.Column(db.String())
    primary_language = db.Column(db.String())
    description = db.Column(db.String())
    release_date = db.Column(db.DateTime)
    parties = db.Column(db.JSON(),default="[]") #separate table?
    keywords = db.Column(db.JSON(),default="[]") #separate table?
    homepage_url = db.Column(db.String())
    download_url = db.Column(db.String())
    size = db.Column(db.Integer)
    sha1 = db.Column(db.String())
    md5 = db.Column(db.String())
    sha256 = db.Column(db.String())
    sha512 = db.Column(db.String())
    bug_tracking_url = db.Column(db.String())
    code_view_url = db.Column(db.String())
    vcs_url = db.Column(db.String())
    copyright = db.Column(db.String())
    license_expression = db.Column(db.String())
    declared_license = db.Column(db.String())
    notice_text = db.Column(db.String())
    root_path = db.Column(db.String())
    contains_source_code = db.Column(db.Boolean)
    source_packages = db.Column(db.JSON(),default="[]") #separate table?
    purl = db.Column(db.String())
    repository_homepage_url = db.Column(db.String())
    repository_download_url = db.Column(db.String())
    api_data_url = db.Column(db.String())
    dependencies = db.relationship('PackageDependency', backref='package', lazy='dynamic')
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class PackageDependency(db.Model):
    __tablename__ = 'package_dependency'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    purl = db.Column(db.String())
    requirement = db.Column(db.String())
    scope = db.Column(db.String())
    is_runtime = db.Column(db.Boolean)
    is_optional = db.Column(db.Boolean)
    is_resolved = db.Column(db.Boolean)
    package_id = db.Column(db.Integer, db.ForeignKey('file_package.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileEmail(db.Model):
    __tablename__ = 'file_email'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    email = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileUrl(db.Model):
    __tablename__ = 'file_url'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    url = db.Column(db.String())
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class FileScanError(db.Model):
    __tablename__ = 'file_scan_error'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    errors = db.Column(db.JSON(),default="[]")
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    repo_id = db.Column(db.Integer)
    repo_name = db.Column(db.String())
    scan_id = db.Column(db.Integer)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class User(db.Model, UserMixin,LogMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(100), unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')
    first_name = db.Column(db.String(100), nullable=False, server_default='')
    last_name = db.Column(db.String(100), nullable=False, server_default='')
    roles = db.relationship('Role', secondary='user_roles')

    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def pretty_roles(self):
        data = []
        for role in self.roles:
            data.append(role.name.lower())
        return data

    def can_edit_roles(self):
        return "admin" in self.pretty_roles()

    def has_role(self,name):
        if not name:
            return False
        if not isinstance(name,list):
            name = [name]
        all_roles = self.pretty_roles()
        for i in name:
            if i.lower() in all_roles:
                return True
        return False

    def set_roles_by_name(self,roles):
        #roles = ["Admin","Another Role"]
        if not isinstance(roles,list):
            roles = [roles]

        new_roles = []
        for role in roles:
            found = Role.query.filter(Role.name == role).first()
            if found:
                new_roles.append(found)
        self.roles[:] = new_roles
        db.session.commit()
        return True

    def is_privileged(self):
        if self.has_role(["admin"]):
            return True
        return False

# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class UserInvitation(db.Model):
    __tablename__ = 'user_invitations'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class ConfigStore(db.Model,LogMixin):
    __tablename__ = 'config_store'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String())
    object_store = db.Column(db.JSON(),default="{}")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def get_object(key):
        '''ConfigStore.get_object("mykey")'''
        store = ConfigStore.query.first()
        if store:
            return store.object_store.get(key.lower())
        return False

    @staticmethod
    def insert_object(object):
        '''ConfigStore.insert_object({"mykey":"myvalue"})'''
        if not isinstance(object,dict):
            return False,"Object must be a dictionary"
        store = ConfigStore.query.first()
        if store:
            temp = {**{},**store.object_store}
            for key,value in object.items():
                key = key.lower()
                temp[key] = value
            store.object_store = temp
            db.session.commit()
            return True
        return False

class Logs(db.Model,DateMixin):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    namespace = db.Column(db.String(),nullable=False,default="general")
    log_type = db.Column(db.String(),nullable=False,default="info")
    message = db.Column(db.String(),nullable=False)
    meta = db.Column(db.JSON(),default="[]")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def add_log(self,message,log_type="info",namespace="general",meta={}):
        if log_type.lower() not in ["info","warning","error","critical"]:
            return False
        msg = Logs(namespace=namespace.lower(),message=message,
            log_type=log_type.lower(),meta=meta)
        db.session.add(msg)
        db.session.commit()
        return True

    def get_logs(self,log_type=None,limit=100,as_query=False,span=None,as_count=False,paginate=False,page=1,namespace="general",meta={}):
        '''
        get_logs(log_type='error',namespace="my_namespace",meta={"key":"value":"key2":"value2"})
        '''
        _query = Logs.query.filter(Logs.namespace == namespace.lower()).order_by(Logs.id.desc())
        if log_type:
            if not isinstance(log_type,list):
                log_type = [log_type]
            _query = _query.filter(Logs.log_type.in_(log_type))

        if meta:
            for key,value in meta.items():
                _query = _query.filter(Logs.meta.op('->>')(key) == value)
        if span:
            _query = _query.filter(Logs.date_added >= arrow.utcnow().shift(hours=-span).datetime)
        if as_query:
            return _query
        if as_count:
            return _query.count()
        if paginate:
            return _query.paginate(page=page, per_page=10)
        return _query.limit(limit).all()

class Tasks(LogMixin,db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.String())
    enabled = db.Column(db.Boolean, default=True)
    module = db.Column(db.String())
    healthy = db.Column(db.Boolean, default=True)
    args = db.Column(db.JSON(),default={})
    start_on = db.Column(db.DateTime)
    last_ran = db.Column(db.DateTime)
    run_every = db.Column(db.Integer,default="10") # in minutes
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def pretty_dt(self,date):
        return arrow.get(date).format("MMM D, HH:mm A")

    @staticmethod
    def ready_to_run():
        tasks = []
        now = arrow.utcnow()
        enabled_tasks = Tasks.query.filter(Tasks.enabled == True).all()
        for task in enabled_tasks:
            if task.module:
                if not task.last_ran: # never ran
                    if not task.start_on or now > arrow.get(task.start_on):
                        tasks.append(task)
                else:
                    minutes = task.run_every or 1
                    if arrow.get(task.last_ran).shift(minutes=minutes) < now:
                        tasks.append(task)
        return tasks

    def was_executed(self):
        now = arrow.utcnow().datetime
        self.last_ran = now
        db.session.commit()

    def get_next_run(self,humanize=False):
        minutes = self.run_every or 0
        if self.last_ran:
            next_run = arrow.get(self.last_ran).shift(minutes=minutes or 1)
        else:
            next_run = arrow.utcnow()
        if humanize:
            return next_run.humanize()
        return next_run
