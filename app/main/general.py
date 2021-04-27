from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, jsonify
from flask_user import current_user, login_required, roles_required, roles_accepted
from . import main
from .. import db
from app.models import Tasks,Role,User

@main.route('/users', methods=['GET'])
@login_required
def users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10)
    return render_template('flask_user/users.html',users=users)

@main.route('/users/<int:id>/roles', methods=['GET','POST'])
@roles_required('Admin')
def edit_user_roles(id):
    user = User.query.get(id)
    if not user:
        flash("User does not exist!")
        return redirect(url_for("main.users"))
    if request.method == "POST":
        roles =  request.form.getlist('roles[]')
        user.set_roles_by_name(roles)
        flash("User roles edited")
        return redirect(url_for("main.users"))
    roles = Role.query.all()
    return render_template('flask_user/edit_user_roles.html',user=user,roles=roles)

@main.route('/users/<int:id>/settings', methods=['GET','POST'])
@login_required
def edit_user_settings(id):
    user = User.query.get(id)
    if not user:
        flash("User does not exist!")
        return redirect(url_for("main.users"))

    if current_user.id != id and not current_user.has_role("admin"):
        flash("You are not authorized to view this page.")
        return redirect(url_for("main.users"))

    if request.method == "POST":
        active = request.form.get("active")
        if active:
            if active == "1":
                user.active = True
            else:
                user.active = False
        flash("User settings edited")
        return redirect(url_for("main.users"))
    return render_template('flask_user/edit_user_status.html',user=user)

@main.route('/tasks', methods=['GET'])
@roles_accepted('Admin')
def tasks():
    page = request.args.get('page', 1, type=int)
    tasks = Tasks.query.order_by(Tasks.id.desc()).paginate(page=page, per_page=15)
    return render_template('flask_user/tasks.html',tasks=tasks)

@main.route('/tasks/<int:id>', methods=['GET','POST'])
@roles_accepted('Admin')
def view_task(id):
    page = request.args.get('page', 1, type=int)
    task = Tasks.query.get(id)
    if not task:
        flash("Task ID does not exist!")
        return redirect(url_for("main.tasks"))

    if request.method == "POST":
        active = request.form.get("active")
        interval = request.form.get("interval")
        if active:
            if active == "1":
                task.enabled = True
            else:
                task.enabled = False
        if interval:
            task.run_every = interval
        db.session.commit()
        flash("Updated Task.")
        return redirect(url_for("main.view_task",id=task.id))
    log_type = None
    if "error" in request.args.get("sort",""):
        log_type = ["error","critical"]
    logs = task.get_logs(log_type=log_type,namespace="jobs",meta={"module":task.module},
        paginate=True,page=page,span=48)
    return render_template('flask_user/view_task.html',task=task,logs=logs)
