#TODO Any URL that is returned as malicious should be added to a block list through the Umbrella API
import requests
import json
import sys
import env
# from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint

inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")

def show_domain_status(domain):
    headers = {"Authorization": f'Bearer {inv_token}'}

    response = requests.get(f"{inv_url}/domains/categorization/{domain}?showLabels", headers=headers)
    response.raise_for_status()

    domain_status = response.json()[domain]["status"]
    if domain_status == 1:
        print(f"---\nThe domain {domain} is found CLEAN\n---".replace('.', '(dot)'))
    elif domain_status == -1:
        print(f"---\nThe domain {domain} is found MALICIOUS\n---".replace('.', '(dot)'))
        
    elif domain_status == 0:
        print(f"---\nThe domain {domain} is found UNDEFINED\n---".replace('.', '(dot)'))
     

def show_historical_info(domain):
    headers = {"Authorization": f'Bearer {inv_token}'}
    
    response = requests.get(f"{inv_url}/pdns/timeline/{domain}", headers=headers)
    response.raise_for_status()

    print(f"---\nThis is the history of the domain reputation from {domain.replace('.','(dot)')}:\n---")
    pprint(response.json(), indent=4)
 

if __name__ == "__main__":
    domain = sys.argv[1]

    show_domain_status(domain)
    show_historical_info(domain)




