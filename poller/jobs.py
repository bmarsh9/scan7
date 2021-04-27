
def scan_assets(task,app,**kwargs):
    Asset = app.tables["asset"]
    assets = app.db_session.query(Asset).all()
