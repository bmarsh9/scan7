from app import db
from flask import current_app
import arrow

class LogMixin(object):
    __table_args__ = {'extend_existing': True}

    def add_log(self,message,log_type="info",meta={},namespace=None):
        logTable = current_app.models["logs"]
        if not namespace:
            namespace = self.__table__.name
        return logTable().add_log(namespace=namespace,message=message,
            log_type=log_type.lower(),meta=meta)

    def get_logs(self,log_type=None,limit=100,as_query=False,span=None,as_count=False,paginate=False,page=1,meta={},namespace=None):
        logTable = current_app.models["logs"]
        if not namespace:
            namespace = self.__table__.name
        return logTable().get_logs(log_type=log_type,namespace=namespace,
            limit=limit,as_query=as_query,span=span,as_count=as_count,
            paginate=paginate,page=page,meta=meta)

class DateMixin(object):
    __table_args__ = {'extend_existing': True}

    def date_arrow(self,field):
        return arrow.get(getattr(self,field))

    def date_humanize(self,field,only_distance=False):
        return arrow.get(getattr(self,field)).humanize(only_distance=only_distance)

    def date_pretty(self,field,format="1"):
        formats = {
          "1":"MMM D",
          "2":"MMM D, HH:mm A",
          "3":"MMM D, HH:mm"
        }
        return arrow.get(getattr(self,field)).format(formats.get(str(format),"1"))
