from flask import jsonify, request, current_app
from . import api
from flask_user import current_user, login_required, roles_required, roles_accepted
from app.utils.apex_constants import get_graph
from app.utils.db_helper import DynamicQuery

@api.route('/apex', methods = ['GET'])
@login_required
def get_apex_chart():
    graph_type = request.args.get('type', None, type=str)
    horizontal = request.args.get('horizontal', False, type=bool)
    if not graph_type:
        return jsonify({"message":"specify type of graph"})
    result = DynamicQuery(
        model=request.args.get('model', "file", type=str),
        request_args=request.args,
        qjson=request.get_json(silent=True)
    )
    response = result.generate()
    if not response:
        return jsonify({"message":"no data available"})

    try:
      if graph_type == "bar":
        d = get_graph("multi_bar")
        d["xaxis"]["categories"] = response["label"]
        series = []
        for point in response["data"]:
            series.append(int(point))
        d["series"] = [{"name":"Count","data":series}]
        d["yaxis"]["title"]["text"] = "Count"
        d["chart"]["height"] = "{}px".format(request.args.get('height', "250", type=str))
        d["plotOptions"]["bar"]["horizontal"] = horizontal

      if graph_type == "area":
        d = get_graph("simple_line")
        series = {"name":"Count","data":[]}
        for point in response["data"]:
            series["data"].append(int(point))
        d["series"] = [series]
        d["labels"] = [x.capitalize() for x in response["label"]]
        d["chart"]["height"] = "{}px".format(request.args.get('height', "250", type=str))

      elif graph_type == "donut":
        d = get_graph("donut")
        d["labels"] = [x.capitalize() for x in response["label"]]
        series = []
        for point in response["data"]:
            series.append(int(point))
        d["series"] = series
        d["chart"]["height"] = "{}px".format(request.args.get('height', "250", type=str))

      d["title"]["text"] = request.args.get('title', "Add title", type=str).capitalize()
      d["theme"] = {"palette":"palette1"}
      d.pop("colors",None)
      return jsonify(d)
    except Exception as e:
        current_app.logger.warning("Exception caught while drawing graphs:{}".format(str(e)))
    return jsonify({"message":"no data available"})
