import requests
from elasticsearch import Elasticsearch, helpers, TransportError
from dotenv import load_dotenv
import json
import time
import xmltodict
import os
from datetime import datetime, timezone, timedelta
import urllib3
import hashlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

# Setup constants and configuration
NESSUS_URL = os.getenv('NESSUS_URL')
NESSUS_ACCESS_KEY = os.getenv('NESSUS_ACCESS_KEY')
NESSUS_SECRET_KEY = os.getenv('NESSUS_SECRET_KEY')
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL')
ELASTICSEARCH_INDEX = os.getenv('ELASTICSEARCH_INDEX')
ELASTICSEARCH_API_KEY = os.getenv('ELASTICSEARCH_API_KEY')
CUSTOMER = os.getenv('CUSTOMER')
HEADERS = {'X-ApiKeys': f'accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}'}
ELASTIC =  Elasticsearch(
        hosts=[ELASTICSEARCH_URL],
        api_key=ELASTICSEARCH_API_KEY,
        request_timeout=30
    )

def get_my_scan_folder_id():
    response = requests.get(f'{NESSUS_URL}/scans', headers=HEADERS, verify=False)
    folders = response.json()['folders']

    for folder in folders:
        if folder['name'] == 'My Scans':
            return folder['id']

    return "No folder found"

def get_scans():
    response = requests.get(f'{NESSUS_URL}/scans', headers=HEADERS, verify=False)
    return response.json()

def get_scan_info(id):
    response = requests.get(f'{NESSUS_URL}/scans/{id}', headers=HEADERS, verify=False)
    return response.json()['info']

def has_already_been_imported(uuid):
    """
    Check if a given UUID exists in an Elasticsearch index.

    Args:
        es (Elasticsearch): The Elasticsearch client instance.
        index (str): The name of the Elasticsearch index to search.
        uuid (str): The UUID to check for existence.

    Returns:
        bool: True if the UUID exists in the index, False otherwise.
    """
    # Construct the search query to find the UUID
    query = {
        "query": {
            "term": {
                "nessus.scan.uuid": uuid  # Assuming 'uuid' is the field name and it's not analyzed
            }
        }
    }
    
    # Execute the search query
    response = ELASTIC.search(index=ELASTICSEARCH_INDEX, body=query)
    
    # Check if there are any hits
    return response['hits']['total']['value'] > 0
    #return False

def get_vuln_hash(ip, port, protocol, plugin_id):
    """
    Generate a unique hash for a vulnerability based on the target IP, port, protocol, and plugin ID.

    Args:
        ip (str): The IP address of the target host.
        port (int): The port number of the service.
        protocol (str): The transport protocol of the service (e.g., 'tcp', 'udp').
        plugin_id (int): The Nessus plugin ID of the vulnerability.

    Returns:
        str: A unique hash string for the vulnerability.
    """
    # Concatenate the Customer, IP, port, protocol, and plugin ID into a unique string
    vuln_str = f"{CUSTOMER}/{ip}:{port}/{protocol}/plugin_id:{plugin_id}"
    # Calculate the hash of the string and return it
    return hashlib.sha256(vuln_str.encode()).hexdigest()

def initiate_scan_export(scan_id, file_format='nessus'):
    data = json.dumps({'format': file_format})
    headers = {**HEADERS, 'Content-Type': 'application/json'}
    response = requests.post(f'{NESSUS_URL}/scans/{scan_id}/export', headers=headers, data=data, verify=False)
    return response.json()

def download_export(scan_id, file_id):
    response = requests.get(f'{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download', headers=HEADERS, verify=False)
    return response.content

def check_export_status(scan_id, file_id):
    response = requests.get(f'{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status', headers=HEADERS, verify=False)
    return response.json()

def convert_xml_to_json(xml_data):
    parsed_xml = xmltodict.parse(xml_data)
    return json.dumps(parsed_xml, indent=4)

def save_failed_data(data, folder="lost"):
    """
    Saves the failed data to a file with a unique identifier in the specified folder.
    """
    os.makedirs(folder, exist_ok=True)
    filename = os.path.join(folder, f"failed_{int(time.time())}.json")
    with open(filename, 'w') as file:
        json.dump(data, file)
    print(f"Data saved to {filename} due to repeated failures.")

def try_index_data(index, data, max_retries=5, delay=10):
    """
    Try to index data into Elasticsearch with retries on failure.

    Args:
        es (Elasticsearch): Elasticsearch client instance.
        index (str): The index name.
        data (dict): The data to index.
        max_retries (int): Maximum number of retries.
        delay (int): Delay between retries in seconds.
    """
    for attempt in range(max_retries):
        try:
            response = ELASTIC.index(index=index, body=data)
            return response
        except TransportError as e:
            print(f"Attempt {attempt + 1} failed: {e.info if hasattr(e, 'info') else e}")
            time.sleep(delay)
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
            time.sleep(delay)
    # After all retries, save the data to a file
    save_failed_data(data)

def unix_to_elastic_timestamp(timestamp):
    """
    Convert a UNIX timestamp or a human-readable timestamp string to an Elasticsearch-compatible, 
    timezone-aware ISO 8601 format.
    
    Args:
        timestamp (int or str): The UNIX timestamp or a human-readable timestamp string.
    
    Returns:
        str: A timezone-aware ISO 8601 formatted timestamp with precision down to milliseconds.
    """
    try:
        # Attempt to treat the input as a UNIX timestamp (int or float)
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp, timezone.utc)
        else:
            # Attempt to parse a human-readable timestamp string
            dt = datetime.strptime(timestamp, '%a %b %d %H:%M:%S %Y')
            dt = dt.replace(tzinfo=timezone.utc)
        
        # Format the datetime object to ISO 8601 with milliseconds and append 'Z' for UTC
        elastic_timestamp = dt.isoformat(timespec='milliseconds') + 'Z'
        return elastic_timestamp
    except ValueError as e:
        raise ValueError(f"Invalid timestamp format: {e}")

def remove_empty_values(data):
    """
    Recursively remove keys with empty string values and empty dictionaries from a dictionary.

    Args:
        data (dict or list): The data structure from which to remove keys with empty values.

    Returns:
        dict or list: The cleaned data structure with empty values removed.
    """
    if isinstance(data, dict):
        # Process each key in the dictionary
        cleaned_dict = {k: remove_empty_values(v) for k, v in data.items() if v != ''}
        # Return dictionary that filters out empty strings and empty dictionaries
        return {k: v for k, v in cleaned_dict.items() if v or isinstance(v, (int, float, bool))}
    elif isinstance(data, list):
        # Recursively clean each item in the list
        return [remove_empty_values(item) for item in data if item != '' or isinstance(item, (int, float, bool, dict, list))]
    else:
        return data

def parse_cvss_v3_vector(cvss_vector):
    """
    Parses a CVSS v3 vector string into a dictionary of metrics and their values.

    Args:
        cvss_vector (str): CVSS v3 vector string, e.g., "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".

    Returns:
        dict: Dictionary with each CVSS v3 metric as keys and their corresponding values.
    """
    # Check if the vector string is empty or None
    if not cvss_vector:
        return {}

    # Split the vector string into components
    vector_components = cvss_vector.split('/')
    
    # Parse each component into a dictionary
    vector_dict = {}
    for component in vector_components:
        if ':' in component:
            metric, value = component.split(':')
            vector_dict[metric] = value

    print(vector_dict)
    return vector_dict
    
def build_data(host, scan_id, scan_name, target):
    info = get_scan_info(scan_id)
    timestamp = info['timestamp'].isoformat(timespec='milliseconds') + 'Z'

    credentialed_scan = None
    cpe = None
    os = None
    mac = None
    netbios = None
    ip = None  
    rdns = None
    state = None

    for tag in host['HostProperties']['tag']:
        match tag['@name']:
            case 'Credentialed_Scan':
                credentialied_scan = tag['#text']
            case 'cpe':
                cpe = tag['#text']
            case 'mac-address':
                mac = tag['#text']
            case 'operating-system':
                os = tag['#text']
            case 'netbios-name':
                netbios = tag['#text']
            case 'host-ip':
                ip = tag['#text']
            case 'host-rdns':
                rdns = tag['#text']

    for item in host['ReportItem']:
        vuln_hash = get_vuln_hash(ip, item.get('@port', ''), item.get('@protocol', ''), item.get('@pluginID', '')),

        data = {
            "@timestamp": timestamp,
            "destination": {
                "port": item.get('@port', ''),
                "service": item.get('@svc_name', '')
            },
            "event": {
                "category": "",
                "kind": "",
                #"duration": int(timestamp_to_unix(info.get('scan_end', 0))) - int(timestamp_to_unix(info.get('scan_start', 0))),
                "start": unix_to_elastic_timestamp(info.get('scan_start', 0)),
                "end": unix_to_elastic_timestamp(info.get('scan_end', 0)),
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
                "name": host.get('@name', ''),
                "netbios": netbios,
                "os": {
                    "cpe": cpe,
                    "full": os,
                    "name": os,
                }
            },
            "nessus": {
                "scan": {
                    "uuid": info.get('uuid', ''),
                    "name": scan_name,
                    "customer": CUSTOMER,
                    "target": target
                },
                "cve": item.get('cve', ''),
                "solution": item.get('solution', ''),
                "synopsis": item.get('synopsis', ''),
                "unsupported_os": "",
                "system_type": "",
                "credentialed_scan": credentialed_scan,
                "exploit_available": item.get('exploit_available', ''),
                "unsupported_by_vendor": "",
                "rdns": rdns,
                "name_of_host": host.get('@name', ''),
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
                    "id": item.get('@pluginID', ''),
                    "name": item.get('@pluginName', ''),
                    "publication_date": item.get('plugin_publication_date', ''),
                    "type": item.get('plugin_type', ''),
                    "output": item.get('plugin_output', ''),
                    "family": item.get('@pluginFamily', '')
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
                "transport": item.get('@protocol', '')
            },
            "vulnerability": {
                "age": item.get('age_of_vuln', ''),
                "category": item.get('@pluginFamily', ''),
                "description": item.get('description', ''),
                "severity": item.get('risk_factor', ''),
                "reference": item.get('see_also', ''),
                "report_id": info.get('uuid', ''),
                "port": item.get('@port', ''),
                "protocol": item.get('@protocol', ''),
                "hash": vuln_hash
            }
        }
        data = remove_empty_values(data)
        try_index_data(ELASTICSEARCH_INDEX, data)

def main():
    scans = get_scans()
    folder_id = get_my_scan_folder_id()

    for scan in scans['scans']:
        if scan['folder_id'] != folder_id:
            continue

        scan_id = scan['id']
        info = get_scan_info(scan_id)
        print(f"Processing scan: {info['name']}")
        export_response = initiate_scan_export(scan_id)
        file_id = None

        if has_already_been_imported(info.get('uuid', '')):
            print("This scan has been imported already")
            continue

        if 'file' in export_response:
            file_id = export_response['file']
        else:
            continue
        
        # Check export status
        while True:
            status_response = check_export_status(scan_id, file_id)
            if status_response['status'] == 'ready':
                break
            time.sleep(5)  # Wait for 5 seconds before checking again

        xml_data = download_export(scan_id, file_id)
        json_data = json.loads(convert_xml_to_json(xml_data))

        scan_name = json_data['NessusClientData_v2']['Report']['@name']
        target = None

        for perf in json_data['NessusClientData_v2']['Policy']['Preferences']['ServerPreferences']['preference']:
            if 'TARGET' in perf['name']:
                target = perf['value']

        if isinstance(json_data['NessusClientData_v2']['Report']['ReportHost'], list):
            for host in json_data['NessusClientData_v2']['Report']['ReportHost']:
                build_data(host, scan_id, scan_name, target)
        else:
            host = json_data['NessusClientData_v2']['Report']['ReportHost']
            build_data(host, scan_id, scan_name, target)

if __name__ == '__main__':
    main()
