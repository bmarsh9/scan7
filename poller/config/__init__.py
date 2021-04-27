from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
import os
import sqlalchemy

db = automap_base()
Base = declarative_base()

class Config():
    def __init__(self,base_dir):
        # create connection to db
        db_uri = 'postgresql://db1:db1@postgres_db/db1'
        db_engine = sqlalchemy.create_engine(db_uri)
        db.prepare(db_engine,reflect=True)
        self.db_session = Session(db_engine)

        # create table mapper
        self.tables = {}
        for obj in db.classes:
            name = str(obj.__table__)
            table_object = getattr(db.classes,name)
            self.tables[name] = table_object

        jobs = [
            {"name":"scan assets","description":"run scans against assets","run_every":1,"module":"scan_assets","enabled":True},
        ]
        Tasks = self.tables["tasks"]
        for job in jobs:
            ex = self.db_session.query(Tasks).filter(Tasks.module==job["module"]).first()
            if ex:
                Tasks.description = job["description"]
                Tasks.run_every = job["run_every"]
                Tasks.enabled = job["enabled"]
            else:
                j = Tasks(**job)
                self.db_session.add(j)
            self.db_session.commit()
