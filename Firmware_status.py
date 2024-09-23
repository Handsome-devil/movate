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
                device_name = device.get('name')
                if 'MX' in device['model'] and device['firmware'].startswith('Not running'):
                    output.append(f"{network_name},{network_id}\n")
                    print(f"{device_name}/{network_name} not running configured Firmware\n")
                else:
                    print(f"{device_name}/{network_name} is running Configured firmware\n")
    with open('Firmware_status1.txt', 'w') as file:
        file.writelines(output)
print(f"Script completed !!")

if __name__ == "__main__":
    main()