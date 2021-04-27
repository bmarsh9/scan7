from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, jsonify
from . import main
from .. import db
from flask_user import current_user, login_required, roles_required, roles_accepted
from app.models import *
import arrow

@main.route('/', methods=['GET'])
@login_required
def home():
    now = arrow.utcnow().shift(days=-7)
    repo_count = Repository.query.count()
    recent_vuln = FileVuln.query.filter(FileVuln.date_added >= now.datetime).count()
    recent_secret = FileSecret.query.filter(FileSecret.date_added >= now.datetime).count()
    return render_template("home.html",repo_count=repo_count,
        recent_vuln=recent_vuln,recent_secret=recent_secret)

@main.route('/keys', methods=['GET'])
@login_required
def keys():
    page = request.args.get('page', 1, type=int)
    keys = GitKey.query.paginate(page=page, per_page=10)
    return render_template("keys.html",keys=keys)

@main.route('/keys/<int:id>', methods=['GET'])
@login_required
def view_key(id):
    key = GitKey.query.get(id)
    if not key:
        flash("Key does not exist!","warning")
        return redirect(url_for("main.keys"))
    return render_template("view_key.html",key=key)

@main.route('/key/add', methods=['POST'])
@login_required
def add_key():
    if request.method == "POST":
        name = request.form["name"]
        key = request.form["key"]
        GitKey().add(name,key)
        flash("Successfully added the key. Repositories can now use it.")
    return render_template("add_key.html")

@main.route('/repositories', methods=['GET'])
@login_required
def repositories():
    page = request.args.get('page', 1, type=int)
    repos = Repository.query.paginate(page=page, per_page=10)
    return render_template("repositories.html",repos=repos)

@main.route('/repositories/<int:id>', methods=['GET'])
@login_required
def view_repository(id):
    repo = Repository.query.get(id)
    if not repo:
        flash("Repository does not exist!","warning")
        return redirect(url_for("main.repositories"))
    return render_template("view_repository.html",repo=repo)

@main.route('/repositories/add', methods=['GET','POST'])
@login_required
def add_repository():
    if request.method == "POST":
        name = request.form["name"]
        branch = request.form["branch"]
        type = request.form["type"]
        url = request.form["url"]
        is_private = request.form["is_private"]
        key = request.form["key"]
        try:
            repo = Repository(name=name,branch=branch,type=type,
                url=url,is_private=is_private
            )
            if key:
                repo.git_key = key
            db.session.add(repo)
            db.session.commit()
            flash("Successfully added the repository.")
        except ValueError as e:
            flash(e,"warning")
    keys = GitKey.query.all()
    return render_template("add_repository.html",keys=keys)

@main.route('/repositories/<int:id>/scans', methods=['GET'])
@login_required
def view_repository_scans(id):
    repo = Repository.query.get(id)
    page = request.args.get('page', 1, type=int)
    if not repo:
        flash("Repository does not exist!","warning")
        return redirect(url_for("main.repositories"))

    scans = repo.scans.order_by(RepositoryScan.date_added.desc()).paginate(page=page, per_page=10)
    return render_template("view_repository_scans.html",repo=repo,scans=scans)

@main.route('/repositories/scan/<int:id>', methods=['GET'])
@login_required
def view_repository_summary_for_scan(id):
    scan = RepositoryScan.query.get(id)
    page = request.args.get('page', 1, type=int)
    if not scan:
        flash("Scan does not exist!","warning")
        return redirect(url_for("main.repositories"))
    return render_template("view_repository_scan.html",scan=scan)

@main.route('/repositories/scan/<int:id>/license', methods=['GET'])
@login_required
def view_repository_license_for_scan(id):
    scan = RepositoryScan.query.get(id)
    page = request.args.get('page', 1, type=int)
    if not scan:
        flash("Scan does not exist!","warning")
        return redirect(url_for("main.repositories"))
    return render_template("view_repository_license_for_scan.html",scan=scan)

@main.route('/repositories/scan/<int:id>/vulns', methods=['GET'])
@login_required
def view_repository_vulns_for_scan(id):
    scan = RepositoryScan.query.get(id)
    page = request.args.get('page', 1, type=int)
    if not scan:
        flash("Scan does not exist!","warning")
        return redirect(url_for("main.repositories"))
    return render_template("view_repository_vulns_for_scan.html",scan=scan)

@main.route('/repositories/scan/<int:id>/secrets', methods=['GET'])
@login_required
def view_repository_secrets_for_scan(id):
    scan = RepositoryScan.query.get(id)
    page = request.args.get('page', 1, type=int)
    if not scan:
        flash("Scan does not exist!","warning")
        return redirect(url_for("main.repositories"))
    return render_template("view_repository_secrets_for_scan.html",scan=scan)
