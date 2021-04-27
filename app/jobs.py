from flask import current_app
from app import db
from app.models import *
from app.utils.scancode_helper import ScHelper
from app.utils.vuln_scanner import VulnScanner
from app.utils.secret_scanner import SecretScanner

def run_scancode(task,**kwargs):
    namespace="jobs"
    meta={"module":task.module}
    for repo in Repository.query.filter(Repository.enabled == True).all():
        repo.update_key_last_used()
        clone_dir = repo.get_clone_dir()
        scan = repo.create_scan_object()
        scan.set_status("pending")
        try: # scan for license
            if current_app.config["JOB_DEBUG"]:
                task.add_log("[{}] Starting scan".format(repo.name),namespace=namespace,meta=meta)
            repo.clone(check_host=False)
            result = ScHelper(repo,scan,save_to_db=True).run_scan(clone_dir)
        except Exception as e:
            error = "[{}] Error while performing license scan. Exception:{}".format(repo.name,str(e))
            task.add_log(error,log_type="error",namespace=namespace,meta=meta)
            scan.set_status("failed")

        try: # dependency scan
            if current_app.config["JOB_DEBUG"]:
                task.add_log("[{}] Scanning dependencies".format(repo.name),namespace=namespace,meta=meta)
            vulns_for_repo = VulnScanner(clone_dir).scan()
            for vuln in vulns_for_repo:
                vuln["repo_id"] = repo.id
                vuln["repo_name"] = repo.name
                vuln["scan_id"] = scan.id
                File().add_vulnerability(vuln)
        except Exception as e:
            error = "[{}] Error while performing dependency scan. Exception:{}".format(repo.name,str(e))
            task.add_log(error,log_type="error",namespace=namespace,meta=meta)
            #scan.set_status("failed")

        try: # scan for secrets
            if current_app.config["JOB_DEBUG"]:
                task.add_log("[{}] Scanning for secrets".format(repo.name),namespace=namespace,meta=meta)
            secrets_for_repo = SecretScanner(clone_dir).scan()
            for secret in secrets_for_repo:
                secret["repo_id"] = repo.id
                secret["repo_name"] = repo.name
                secret["scan_id"] = scan.id
                File().add_secret(secret)
        except Exception as e:
            error = "[{}] Error while performing secret scan. Exception:{}".format(repo.name,str(e))
            task.add_log(error,log_type="error",namespace=namespace,meta=meta)
            #scan.set_status("failed")

        scan.set_status("complete")
        if current_app.config["JOB_DEBUG"]:
            task.add_log("[{}] Scan complete".format(repo.name),namespace=namespace,meta=meta)
        repo.clean_clone_dir()
    return True

def get_insights(task,**kwargs):
    '''Run all queries against the data'''
    namespace="jobs"
    meta={"module":task.module}
    return True
