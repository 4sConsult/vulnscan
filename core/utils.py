import json
import os
from datetime import datetime, timezone, timedelta

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