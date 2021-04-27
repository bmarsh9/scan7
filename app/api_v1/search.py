from flask import jsonify, request, current_app
from . import api
from flask_user import current_user, login_required, roles_required, roles_accepted
from app.models import *
from app.utils.db_helper import DynamicQuery

@api.route("/search/<string:model>", methods=["GET"])
@login_required
def search_api(model):
    '''
    API for sqlalchemy database tables
    '''
    result = DynamicQuery(
        model=model,
        request_args=request.args,
        qjson=request.get_json(silent=True)
    )
    response = result.generate()
    return jsonify(response)
