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

def main() -> None:
    output = []

    for network in networks:
        network_id = network['id']
        network_name = network['name']
    # Get the devices in the network
        devices = client.networks.getNetworkDevices(network_id)
        for device in devices:
        # Check if the device is an MX model and has no name (name is null or empty)
            if 'MX' in device['model']: #and not device.get('name')
                output.append(f"{device.get('name')} {network_id} {network_name}\n")
                print(f"Compleated {device.get('name')} - {network_name}!!")

    with open('output.txt', 'w') as file:
        file.writelines(output)

if __name__ == "__main__":
    main()
