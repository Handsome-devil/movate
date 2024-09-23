#!/usr/bin/env python3

import traceback
import json
from unicodedata import normalize
import dotenv
import meraki
from pyzabbix import ZabbixAPI, ZabbixAPIException
from tqdm import tqdm

config = dotenv.dotenv_values()
client = meraki.DashboardAPI(
    config['MERAKI_API_KEY'],
    output_log=False,
    nginx_429_retry_wait_time=3,
    action_batch_retry_wait_time=3,
    print_console=False,
    suppress_logging=True,
    maximum_retries=10)
# zabbix = ZabbixAPI(config['ZABBIX_URL'])
# zabbix.login(api_token=config['ZABBIX_API_TOKEN'])

# dashboard = meraki.DashboardAPI(config['MERAKI_API_KEY'])

networks = client.organizations.getOrganizationNetworks(
        config['ORG_ID'], total_pages='all'
    )

Initial = 0
final = 1

for network in networks:
    old_name = network['name']
    if old_name.startswith('IN') and len(old_name) > 2 and old_name[2] != '-':  # Check if the hyphen is already present
        # Insert hyphen after the first two characters
        new_name = old_name[:2] + '-' + old_name[2:]
        
        # Rename the network
        client.networks.updateNetwork(
            network['id'],
            name=new_name
        )
        Initial += 1
        
        print(f"Renamed '{old_name}' to '{new_name}'")
    else:
        print(f"Skipped renaming '{old_name}'")
    if Initial >= final:
        break

print("Renaming process completed.")