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

# with open('networks-3.txt', 'w', encoding='UTF-8') as f:
#             f.writelines(json.dumps(networks))

def main() -> None:
    # renamed_count = 0
    # max_renames = 5
    output = []
    for network in networks:
        network_id = network['id']
        network_name = network['name']

        # Get the devices in the network
        devices = client.networks.getNetworkDevices(network_id)
    

        for device in devices:
            # Check if the device is an MX model and has no name (name is null or empty)
            if 'MX' in device['model'] and not device.get('name'):
                # Generate the new name
                new_name = f"{network_name} - {device['model']}"
            
                # Update the device name
                client.devices.updateDevice(device['serial'], name=new_name)
                print(f"Renamed {device['serial']} to {new_name}")
                # renamed_count += 1
                output.append(new_name)
            
                # Check if we've renamed 5 devices
                # if renamed_count >= max_renames:
                #     print(f"Renamed {max_renames} devices. Stopping script.")
                #     break
    
        # Stop processing further networks if the limit is reached
        # if renamed_count >= max_renames:
        #     break
        with open('new_name-1.json', 'w', encoding='UTF-8') as f:
            f.writelines(json.dumps(output))

    print("Device renaming complete.")

if __name__ == "__main__":
    main()            
