from config import Config
import jobs as schjobs
import os
import sys
import time
import arrow
import logging

class Poller():
    def __init__(self,app):
        self.Tasks = app.tables["tasks"]

    def run(self):
        while True:
            time.sleep(1)
            for task in self.ready_to_run():
                logging.info("Executing ready task: {}".format(task.module))
                self.was_executed(task)
                args = task.args or {}
                try:
                    result = getattr(schjobs,task.module)(task,app,**args)
                except Exception as e:
                    logging.error("Exception when processing job:{}. Error:{}".format(task.module,e))
                    result = None
                if result:
                    task.healthy = True
                else:
                    task.healthy = False
                app.db_session.commit()

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logging.info("Starting the poller")
    base_dir = os.path.abspath(os.path.dirname(__file__))
    app = Config(base_dir)

    # Start service
    Poller(app).run()
