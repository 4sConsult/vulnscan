from flask import Flask, request
import json
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
import hashlib
from core.utils import *

app = Flask(__name__)
load_dotenv()
CUSTOMER = os.getenv('CUSTOMER')

@app.route('/')
def hello():
    return 'Hello, World!'

@app.route('/transform/<timestamp>', methods=['POST'])
def transform(timestamp):
    json_data = request.get_json()  # Get the JSON data from the request

    scan_name = json_data['NessusClientData_v2']['Report']['$']['name']
    target = None
    host_count = 0
    uuid = None

    vulnerabilities = []

    for perf in json_data['NessusClientData_v2']['Policy']['Preferences']['ServerPreferences']['preference']:
        if 'TARGET' in perf['name']:
            target = perf['value']
        if 'report_task_id' in perf['name']:
            uuid = perf['value']

    for host in json_data['NessusClientData_v2']['Report']['ReportHost']:
        host_count += 1

    for host in json_data['NessusClientData_v2']['Report']['ReportHost']:
        credentialied_scan = None
        cpe = None
        os = None
        mac = None
        netbios = None
        ip = None  
        rdns = None

        for tag in host['HostProperties']['tag']:
            match tag['$']['name']:
                case 'Credentialed_Scan':
                    credentialied_scan = tag['_']
                case 'cpe':
                    cpe = tag['_']
                case 'mac-address':
                    mac = tag['_']
                case 'operating-system':
                    os = tag['_']
                case 'netbios-name':
                    netbios = tag['_']
                case 'host-ip':
                    ip = tag['_']
                case 'host-rdns':
                    rdns = tag['_']

        for item in host['ReportItem']:
            data = {
                "@timestamp": unix_to_elastic_timestamp(int(timestamp) / 1000),
                "destination": {
                    "port": item['$']['port'],
                    "service": item['$']['svc_name']
                },
                "event": {
                    "category": "",
                    "kind": "",
                    "risk_score": item.get('cvss3_base_score', ''),
                    "dataset": "",
                    "provider": "4s Vulnerability Scanner",
                    "message": item.get('description', ''),
                    "module": "sync.py",
                    "severity": item.get('risk_factor', ''),
                    "url": item.get('see_also', '')
                },
                "host": {
                    "ip": ip,
                    "mac": mac,
                    "hostname": rdns,
                    "name": host['$']['name'],
                    "netbios": netbios,
                    "os": {
                        "cpe": cpe,
                        "full": os,
                        "name": os,
                    }
                },
                "nessus": {
                    "scan": {
                        "uuid": uuid,
                        "name": scan_name,
                        "customer": CUSTOMER,
                        "target": target,
                        "host_count": host_count
                    },
                    "cve": item.get('cve', ''),
                    "solution": item.get('solution', ''),
                    "synopsis": item.get('synopsis', ''),
                    "unsupported_os": "",
                    "system_type": "",
                    "credentialed_scan": credentialied_scan,
                    "exploit_available": item.get('exploit_available', ''),
                    "unsupported_by_vendor": "",
                    "rdns": rdns,
                    "name_of_host": host['$']['name'],
                    "cvss": {
                        "base": {
                            "vector": item.get('cvss_vector', ''),
                            "score": item.get('cvss_base_score', '')
                        },
                        "temporal": {
                            "vector": item.get('cvss_temporal_vector', ''),
                            "score": item.get('cvss_temporal_score', '')
                        }
                    },
                    "cvss3": {
                        "base": {
                            "vector": item.get('cvss3_vector', ''),
                            "score": item.get('cvss3_base_score', '')
                        },
                        "temporal": {
                            "vector": item.get('cvss3_temporal_vector', ''),
                            "score": item.get('cvss3_temporal_score', '')
                        }
                    },
                    "plugin": {
                        "id": item['$']['pluginID'],
                        "name": item['$']['pluginName'],
                        "publication_date": item.get('plugin_publication_date', ''),
                        "type": item.get('plugin_type', ''),
                        "output": item.get('plugin_output', ''),
                        "family": item['$']['pluginFamily']
                    },
                    "vpr_score": item.get('vpr_score', ''),
                    "exploit_code_maturity": item.get('exploit_code_maturity', ''),
                    "exploitability_ease": item.get('exploit_ease', ''),
                    "age_of_vuln": item.get('age_of_vuln', ''),
                    "patch_publication_date": item.get('patch_publication_date', ''),
                    "threat": {
                        "intensity_last_28": item.get('threat_intensity_last_28', ''),
                        "recency": item.get('threat_recency', ''),
                        "sources_last_28": item.get('threat_sources_last_28', '')
                    },
                    "vuln_publication_date": item.get('vuln_publication_date', ''),
                },
                "network": {
                    "transport": item['$']['protocol'],
                },
                "vulnerability": {
                    "age": item.get('age_of_vuln', ''),
                    "category": item.get('plugin_output', ''),
                    "description": item.get('description', ''),
                    "severity": item.get('risk_factor', ''),
                    "reference": item.get('see_also', ''),
                    "report_id": uuid,
                    "port": item['$']['port'],
                    "protocol": item['$']['protocol'],
                    "hash": hashlib.sha256(f"{CUSTOMER}/{ip}:{item['$']['port']}/{item['$']['protocol']}/plugin_id:{item['$']['pluginID']}".encode()).hexdigest()
                }
            }
            data = remove_empty_values(data)
            vulnerabilities.append(data)
            
    return vulnerabilities
