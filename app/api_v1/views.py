from flask import jsonify, request, current_app
from . import api
from flask_user import current_user, login_required, roles_required, roles_accepted

@api.route('/health', methods=['GET'])
@login_required
def get_health():
    return jsonify({"message":"ok"})
