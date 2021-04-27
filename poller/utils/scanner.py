#!/usr/bin/python3

from flask import Flask,current_app
import nmap
import datetime
import json
import re
#from zapv2 import ZAPv2
import time
#from app.utils.misc import lookup_ip

class Scanner():
    def __init__(self,target,arguments,include_down_hosts=False,extra_metrics=False,to_csv=False):
        self.nm = nmap.PortScanner()
        self.target = target
        self.arguments = arguments
        self.include_down_hosts = include_down_hosts
        self.extra_metrics= extra_metrics
        self.to_csv = to_csv
        self.target_list = self.nm.listscan(self.target)

        if not self.target_list:
            return "Target list is empty!"

    def execute(self):
        pass

    def port_scan(self):
        result = None
        try:
            self.nm.scan(hosts=self.target, arguments=self.arguments)
        except nmap.nmap.PortScannerError:
            app.logger.error("Failed scan! Check arguments and try disabling script scanning.")
            return False

#        if not self.nm.all_hosts():
#            app.logger.error("No targets were scanned!")
#            return False

        # output options
#        if self.to_csv:
#            return self.nm.csv()

        return self.parse_sync_to_json()

    def parse_sync_to_json(self):
        dataset = {"host_data":[],"targets":self.target}

        # collect scan metrics
        family_dict = {}
        os_dict = {}
        services_dict = {}
        ports_open_dict = {}

        uniq_family = 0
        uniq_os = 0
        total_ports_open = 0
        uniq_ports_open = 0
        total_services = 0
        uniq_services = 0

        # get overall scan details
        scan_start = datetime.datetime.strptime(self.nm.scanstats()["timestr"],"%a %b %d %H:%M:%S %Y")
        scan_end = scan_start + datetime.timedelta(0,float(self.nm.scanstats()["elapsed"]))
        dataset["scan_start"] = str(scan_start)
        dataset["scan_end"] = str(scan_end.replace(microsecond=0))

        scan_stats_keys = ["uphosts","downhosts","totalhosts"]
        for key,value in self.nm.scanstats().items():
            if key in scan_stats_keys:
                dataset[key] = int(value)

        elapsed = 0
        try:
            elapsed = float(round(float(self.nm.scanstats()["elapsed"])/60,2))
        except:
            pass
        dataset["elapsed"] = elapsed

        percentage_up = 0
        try:
            percentage_up = (int(self.nm.scanstats()["uphosts"]) / int(self.nm.scanstats()["totalhosts"]) *100)
        except:
            pass
        dataset["percentage_up"] = int(round(percentage_up))

        # enumerate hosts in scan
        for host in self.nm.all_hosts():
            # set host information
            data = {"port_data":[],"ip":self.nm[host]["addresses"]["ipv4"],"hostname":self.nm[host].hostname(),
                "state":self.nm[host].state(),"uptime":None,"last_boot":None}

            # get geo-ip info
            #geo = lookup_ip(self.nm[host]["addresses"]["ipv4"])
            geo=None
            if geo: #make sure it is a global ip
                data["country_code"] = geo.country_code
                data["country_name"] = geo.country_name
                data["region_name"] = geo.region_name
                data["city_name"] = geo.city_name
                data["lat"] = geo.latitude
                data["long"] = geo.longitude

            if self.nm[host].state() == "up":
                if self.nm[host].get("uptime"):
                    data["uptime"] = self.nm[host]["uptime"].get("seconds")
                    data["last_boot"] = self.nm[host]["uptime"].get("lastboot")

                # enumerate OS version
                indexed_osclass_keys = ["type","vendor","osfamily","osgen"]
                if self.nm[host].get("osmatch"):
                    # get os match with highest accuracy
                    likely_os = sorted(self.nm[host]["osmatch"],key=lambda i: int(i["accuracy"]),reverse=True)[0]
                    data["os"] = likely_os.get("name","unknown")
                    # add uniq os type
                    if not os_dict.get(likely_os.get("name","unknown")):
                        uniq_os += 1
                        os_dict[likely_os.get("name","unknown")] = 1
                    else:
                        os_dict[likely_os.get("name","unknown")] += 1

                    data["accuracy"] = likely_os.get("accuracy",0)

                    # get os_class match with highest accuracy
                    if likely_os.get("osclass"):
                        likely_osclass = sorted(likely_os["osclass"],key=lambda i: int(i["accuracy"]),reverse=True)[0]
                        for key,value in likely_osclass.items():
                            if key in indexed_osclass_keys:
                                # add uniq os family type
                                if key == "osfamily":
                                    if not family_dict.get(value):
                                        uniq_family += 1
                                        family_dict[value] = 1
                                    else:
                                        family_dict[value] += 1
                                data[key] = value
                    data["os_data"] = self.nm[host]["osmatch"][:2] # add full os data for 2 matches

                # per host port metrics
                host_services_list = []
                host_ports_open_list = []
                host_ports_open = 0
                host_services = 0

                # get risk factor
                critical_severity = 0
                high_severity = 0
                medium_severity = 0

                # enumerate all protocols
                indexed_port_keys = ["state","reason","name","product","version","extrainfo","conf","cpe","script"]
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        temp = {}
                        for key,value in self.nm[host][proto][port].items(): # iterate over all ports
                            if key in indexed_port_keys:
                                # add to metrics
                                if key == "state" and value == "open":
                                    host_ports_open += 1
                                    host_ports_open_list.append(port)
                                    total_ports_open += 1
                                    if not ports_open_dict.get(port):
                                        ports_open_dict[port] = 1
                                        uniq_ports_open += 1
                                    else:
                                        ports_open_dict[port] += 1

                                elif key == "name" and value and value != "":
                                    host_services += 1
                                    host_services_list.append(value)
                                    total_services += 1
                                    if not services_dict.get(value):
                                        services_dict[value] = 1
                                        uniq_services += 1
                                    else:
                                        services_dict[value] += 1
                                elif key == "script" and value and value != "":
                                    for k,v in value.items():
                                        try:
                                            if "Risk factor" in v:
                                                temp_severity = re.findall(r'\bRisk factor:\s\w+',v)[0]
                                                severity = temp_severity.split(":")[1].strip()
                                                if severity.lower() == "critical":
                                                    critical_severity+=1
                                                elif severity.lower() == "high":
                                                    high_severity+=1
                                                elif severity.lower() == "medium":
                                                    medium_severity+=1
                                        except:
                                            pass
                                    value = json.dumps(value)
                                temp[key] = value
                        # finalize host data
                        temp["port"] = port
                        temp["protocol"] = proto
                        data["port_data"].append(temp)
                if critical_severity:
                    data["critical_severity"] = critical_severity
                if high_severity:
                    data["high_severity"] = high_severity
                if medium_severity:
                    data["medium_severity"] = medium_severity
                data["ports_open"] = host_ports_open
                data["services"] = host_services
                dataset["host_data"].append(data)
            # down host
            else:
                if self.include_down_hosts:
                    dataset["host_data"].append(data)

        # insert overall metrics
        dataset["uniq_family"] = uniq_family
        dataset["uniq_os"] = uniq_os
        dataset["total_ports_open"] = total_ports_open
        dataset["uniq_ports_open"] = uniq_ports_open
        dataset["total_services"] = total_services
        dataset["uniq_services"] = uniq_services

        # insert meta data if requested
        if self.extra_metrics:
            #dataset["meta_family"] = {v: k for v, k in enumerate(family_dict,1)} # DEP
            dataset["meta_services"] = services_dict
            dataset["meta_ports"] = ports_open_dict
            dataset["meta_os"] = os_dict
            dataset["meta_family"] = family_dict

        # return results of the scan
        return dataset

    def app_scan(self,target,sleep_time=2):
        data = {}
        zap = ZAPv2()
        sessionName="sample"
        zap.core.new_session(name=sessionName, overwrite=True)

        contextIncludeURL = [self.target]
        contextName="sample"
        zap.context.new_context(contextname=contextName)

        for url in contextIncludeURL:
            zap.context.include_in_context(contextname=contextName,
                regex=url)

        scanID = zap.spider.scan(target)
        while int(zap.spider.status(scanID)) < 100:
            spider_status = zap.spider.status(scanID)
            time.sleep(sleep_time)

        urls = zap.spider.results(scanID)

        total_records = int(zap.pscan.records_to_scan)
        while int(zap.pscan.records_to_scan) > 0:
            passive_status = 100 - ((int(zap.pscan.records_to_scan) / total_records) *100)
            time.sleep(sleep_time)

        hosts = zap.core.hosts
        alerts = zap.core.alerts()

        data["target"] = target
        data["alerts"] = alerts
        data["urls"] = urls

        return data
