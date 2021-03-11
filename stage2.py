#TODO check AMP for events on a host (Demo_AMP_Threat_Audit)
#TODO If it returns any events with type Executed malware:
#TODO   list the information
#TODO   isolate the host with AMP 
#TODO   and investigate the chosen file hash(es) through Threatgrid.
#TODO Check Threatgrid for the domains that have been seen for the sample and save that information in a file
import requests
import json
import env
from pprint import pprint

um_en_host = env.AMP.get("host")
um_en_client_id = env.AMP.get("client_id")
um_en_api_key = env.AMP.get("api_key")

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
            return True

if __name__ == "__main__":
    list_events = get_events()
    find_executed_malware_events_host(list_events, hostname)

