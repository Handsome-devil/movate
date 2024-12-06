#!/usr/bin/env python3

import pandas as pd
from pyzabbix import ZabbixAPI
import dotenv

config = dotenv.dotenv_values()

# Connect to Zabbix
try:
    zabbix = ZabbixAPI(config['ZABBIX_URL'])
    zabbix.login(api_token=config['ZABBIX_API_TOKEN'])
    print(f"ZABBIX_API_TOKEN: {config.get('ZABBIX_API_TOKEN')}")
    print("Successfully connected to Zabbix.")
except Exception as e:
    print(f"Connection failed: {e}")
    exit()

# Fetch hosts
try:
    hosts = zabbix.host.get(
        output=["hostid", "host", "name", "status"],
        selectInterfaces=["ip", "port"]  # Fetching network interface information including port
    )
    print(f"Fetched {len(hosts)} hosts.")
    
    # Prepare data for export
    host_data = []
    for host in hosts:
        for interface in host.get('interfaces', []):  # Loop over interfaces if there are multiple
            host_data.append({
                "Host ID": host["hostid"],
                "Host": host["host"],
                "Name": host["name"],
                "Status": host["status"],
                "IP Address": interface.get("ip", "N/A"),  # Fallback if no IP is available
                "Port": interface.get("port", "N/A")  # Fallback if no port is available
            })
    
    # Convert the data into a DataFrame
    df = pd.DataFrame(host_data)
    
    # Export to Excel
    df.to_excel('zabbix_hosts_inventory_export_demo.xlsx', index=False)
    print("Hosts and inventory details exported successfully to 'zabbix_hosts_inventory_export_demo.xlsx'.")

except Exception as e:
    print(f"Failed to fetch hosts: {e}")


