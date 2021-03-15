import requests
import json
import env
from pprint import pprint

um_en_host = env.AMP.get("host")
um_en_client_id = env.AMP.get("client_id")
um_en_api_key = env.AMP.get("api_key")

threatgrid_host = env.THREATGRID.get("host")
threatgrid_api_key = env.THREATGRID.get("api_key")

hostname = 'Demo_AMP_Threat_Audit'

def get_events():
    headers = {
        'Content-Type': 'application/json'
    }

    # event_type_id 1107296272 corresponds to event_type Executed Malware
    response = requests.get(f"https://{um_en_client_id}:{um_en_api_key}@{um_en_host}/v1/events?event_type[]=1107296272", headers=headers)
    response.raise_for_status()

    list_events = response.json()['data']

    return list_events

def find_executed_malware_events_host(list_events, hostname):
    for event in list_events:
        if event['computer']['hostname'] == hostname:
            pprint(event, indent=4)
            connector_guid = event['computer']['connector_guid']
            sha256 = event['file']['identity']['sha256']
    
    return connector_guid, sha256

def isolate_host(connector_guid):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    response = requests.put(f"https://{um_en_client_id}:{um_en_api_key}@{um_en_host}/v1/computers/{connector_guid}/isolation", headers=headers)
    
    # Commented this out, because the host is already in an isolated state
    # response.raise_for_status()

def check_sample_state(sha256):
    response = requests.get(f"https://{threatgrid_host}/api/v2/search/submissions?api_key={threatgrid_api_key}&q={sha256}")
    response.raise_for_status()

    # It doesn't matter which sample we choose, as long as they have the specified sha256
    return response.json()['data']['items'][0]['item']['sample']

def check_domains(sample_id):
    response = requests.get(f"https://{threatgrid_host}/api/v2/samples/feeds/domains?sample={sample_id}&api_key={threatgrid_api_key}")
    response.raise_for_status()

    pprint(response.json(), indent=4)

    return response.json()['data']['items']

if __name__ == "__main__":
    list_events = get_events()

    print('The following are found executed malware events:\n---\n')
    connector_guid, sha256 = find_executed_malware_events_host(list_events, hostname)

    isolate_host(connector_guid)
    print('---\nThe host has been isolated!\n---\n')

    sample_id = check_sample_state(sha256)
    print('---\nThe file hash has been checked with Threatgrid\n---\n')

    
    domains = check_domains(sample_id)

    # Writes the domains which have seen the sample to domains.json
    with open('domains.json', 'w') as output_file:
        json.dump(domains, output_file)
    
    print('---\nDomains which have been seen for sample, have been saved to domains.json')

