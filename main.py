#!/usr/bin/env python3

import traceback
import json
from unicodedata import normalize
import dotenv
import meraki
from pyzabbix import ZabbixAPI, ZabbixAPIException
from tqdm import tqdm

# Setup
config = dotenv.dotenv_values()
client = meraki.DashboardAPI(
    config['MERAKI_API_KEY'],
    output_log=False,
    nginx_429_retry_wait_time=3,
    action_batch_retry_wait_time=3,
    print_console=False,
    suppress_logging=True,
    maximum_retries=10)
zabbix = ZabbixAPI(config['ZABBIX_URL'])
zabbix.login(api_token=config['ZABBIX_API_TOKEN'])

def create_host(api_data) -> bool:
    """
    Creates a host in Zabbix.
    """
    create_data = {
        'host': api_data['network_id'],
        'name': api_data['name'],
        'interfaces': [
            {
                'type': 2,
                'main': 1,
                'useip': 1,
                'ip': api_data['appliance_ip'],
                'dns': '',
                'port': '161',
                'details': {
                    'version': 2,
                    'community': config['ZABBIX_SNMP_COMMUNITY']
                }
            }
        ],
        'groups': [
            {'groupid': '5'} 
        ],
        'templates': [
            {'templateid': config['ZABBIX_TEMPLATE_ID']}
        ],
        'inventory_mode': 0,
        'inventory': {
            'name': api_data['name'],
            'location_lat': api_data['lat'],
            'location_lon': api_data['lng'],
            'model': api_data['model'],
            'url_a': api_data['url'],
            'os_full': api_data['mx_firmware'],
            'serialno_a': api_data['serial']
        }
    }
    try:
        tqdm.write(f"\t[+] Creating host '{api_data['network_id']}'")
        zabbix.do_request('host.create', create_data)
        return True
    except ZabbixAPIException:
        tqdm.write(traceback.format_exc())
        tqdm.write(f"\t[!] Error creating host '{api_data['network_id']}'")
        return False

def update_inventory(host_data, host_id) -> bool:
    """
    Updates the inventory of the host.
    """
    inventory_data = {
        'hostid': host_id,
        'inventory_mode': 0,
        'inventory': {
            'name': host_data['name'],
            'location_lat': host_data['lat'],
            'location_lon': host_data['lng'],
            'model': host_data['model'],
            'url_a': host_data['url'],
            'os_full': host_data['mx_firmware'],
            'serialno_a': host_data['serial']
        }
    }
    try:
        """tqdm.write(f"\t\t[+] Updating inventory for host '{host_data['network_id']}'")"""
        zabbix.do_request('host.update', inventory_data)
        return True
    except ZabbixAPIException:
        tqdm.write(traceback.format_exc())
        tqdm.write(f"\t\t[!] Error updating inventory for host '{host_data['network_id']}'")
        return False

def update_host(host_data, host_id) -> bool:
    """
    Updates the host in Zabbix.
    """
    update_data = {
        'hostid': host_id,
        'name': host_data['name']
    }
    try:
        """tqdm.write(f"\t\t[+] Updating host {host_data['network_id']}")"""
        zabbix.do_request('host.update', update_data)
        return True
    except ZabbixAPIException:
        tqdm.write(traceback.format_exc())
        tqdm.write(f"\t\t[!] Error updating host {host_data['network_id']}")
        return False

def disable_icmp_ping_item(host_id: str) -> bool:
    """
    Disables the ICMP Ping item.
    """
    items = zabbix.item.get(hostids=[host_id], search={'key_': 'icmp.ping'})
    for item in items:
        try:
            """tqdm.write(f"\t\t[+] Disabling ICMP Ping item for host '{host_id}'")"""
            zabbix.do_request('item.update', {'itemid': item['itemid'], 'status': 1})
            return True
        except ZabbixAPIException:
            tqdm.write(traceback.format_exc())
            tqdm.write(f"\t\t[!] Error disabling ICMP Ping item for host '{host_id}'")
            return False
    return True


def get_network_vlans(network_id: str) -> dict:
    """
    Gets the VLANs of a network.
    
    Args:
        network_id: The network ID.
    """
    """tqdm.write(f"[+] Working on {network_id}")"""
    try:
        res = client.appliance.getNetworkApplianceVlans(
            network_id
        )
    except meraki.exceptions.APIError:
        res = {}
    return res

def upsert_host(api_data: dict, zabbix_data: dict) -> bool:
    """
    Upserts a host in Zabbix.

    Args:    
        api_data: The data from the Meraki API.
        zabbix_data: The data from Zabbix.
    """
    if zabbix_data:
        # update
        host_id = zabbix_data[0]['hostid']
        """tqdm.write(f"\t[+] Host '{host_id}' already exists. Updating...")"""
        a = disable_icmp_ping_item(host_id)
        b = update_host(api_data, host_id)
        c = update_inventory(api_data, host_id)
        return a and b and c
    else:
        # create
        tqdm.write("\t[+] Host does not exist. Creating...")
        if create_host(api_data):
            return True
    return False

def check_device_type(device: dict) -> bool:
    """
    Checks if the device is an MX or VMX.
    
    Args:
        device: The device.
    """
    model = device['model'].startswith('MX') or device['model'].startswith('VMX')
    running = not device['firmware'].startswith('Not running')
    # name = device['name'] is not None and device['name'] != ''
    return model and running# and name

def main() -> None:
    """
    Entry point of the program.
    """

    tqdm.write("[+] Fetching Organization Devices...")

    # https://developer.cisco.com/meraki/api-v1/get-organization-devices/
    devices = client.organizations.getOrganizationDevices(
        config['ORG_ID'], total_pages='all'
    )
    
    mx_devices = []

    for device in devices:
        if check_device_type(device):
            mx_devices.append(device)
    
    tqdm.write(f"[+] Done! {len(mx_devices)} MX/VMX devices found.")

    final_data = []
    errors = []

    for device in tqdm(mx_devices):
        network_id = device['networkId']
        vlans = get_network_vlans(network_id)
        if not vlans:
            continue
        for vlan in vlans:
            if "Corporate" in vlan['name'] or "Default" in vlan['name']:
                vlans = vlan
                try:
                    device = {
                        'network_id': network_id,
                        'serial': device['serial'],
                        'name': normalize('NFKD', device['name']).encode('ascii', 'ignore').decode(),
                        'model': device['model'],
                        'lat': str(device['lat'])[:16],
                        'lng': str(device['lng'])[:16],
                        'tags': device['tags'],
                        'url': device['url'],
                        'mx_firmware': device['firmware'],
                        'vlan_id': vlans['id'],
                        'vlan_name': vlans['name'],
                        'appliance_ip': vlans['applianceIp']
                        }
                    final_data.append(device)
                    host = zabbix.host.get(filter={'host': network_id})
                    if upsert_host(device, host):
                        """tqdm.write(f"\t[+] Host '{network_id}' upserted successfully.")"""
                    else:
                        tqdm.write(f"\t[!] Error with network id: {network_id}")
                        errors.append(device)
                    break
                except Exception:
                    tqdm.write(f"[!] Error with {device}")
                    tqdm.write(traceback.format_exc())
                    errors.append(device)

    # with open('output.json', 'w', encoding='UTF-8') as f:
    #     f.write(json.dumps(final_data))
    if errors:
        with open('errors.json', 'w', encoding='UTF-8') as f:
            f.write(json.dumps(errors))

if __name__ == "__main__":
    main()
