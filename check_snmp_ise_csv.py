import requests
import json
import csv
from requests.auth import HTTPBasicAuth

# Konfigurationsparameter
ISE_IP = "192.168.1.100"  # Ersetze mit der IP der Cisco ISE
USERNAME = "api_user"
PASSWORD = "password123"
CSV_FILE = "devices_without_snmp.csv"

# API URL
BASE_URL = f"https://{ISE_IP}:9060/ers/config/networkdevice"
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def get_network_devices():
    """ Ruft alle Network Devices aus Cisco ISE ab """
    try:
        response = requests.get(BASE_URL, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
        response.raise_for_status()
        return response.json().get("SearchResult", {}).get("resources", [])
    except requests.HTTPError as e:
        print(f"HTTP Error: {e}")
        return []
    except Exception as e:
        print(f"Fehler beim Abrufen der Network Devices: {e}")
        return []

def check_snmp_config(device_id):
    """ Prüft die SNMP-Konfiguration eines Network Devices """
    try:
        device_url = f"{BASE_URL}/{device_id}"
        response = requests.get(device_url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
        response.raise_for_status()
        device_data = response.json().get("NetworkDevice", {})
        
        # Prüfen, ob SNMP konfiguriert ist
        snmp_settings = device_data.get("snmpsettings", [])
        if not snmp_settings:
            # Hole die IP-Adresse
            ip_address = device_data.get("ipaddress", {}).get("ipaddress", "Unbekannt")
            return device_data.get("name", "Unbekannt"), ip_address
    except Exception as e:
        print(f"Fehler beim Prüfen der SNMP-Konfiguration für Device {device_id}: {e}")
    
    return None

def write_to_csv(data):
    """ Schreibt die Daten in eine CSV-Datei """
    try:
        with open(CSV_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Device Name", "IP Address"])
            writer.writerows(data)
        print(f"Erfolgreich in {CSV_FILE} geschrieben.")
    except Exception as e:
        print(f"Fehler beim Schreiben der CSV-Datei: {e}")

def main():
    print("Suche nach Network Devices ohne SNMP-Konfiguration...\n")
    devices = get_network_devices()
    
    if not devices:
        print("Keine Network Devices gefunden.")
        return
    
    devices_without_snmp = []

    for device in devices:
        device_id = device.get("id")
        result = check_snmp_config(device_id)
        
        if result:
            devices_without_snmp.append(result)

    if devices_without_snmp:
        write_to_csv(devices_without_snmp)
    else:
        print("Alle Network Devices haben SNMP konfiguriert.")

if __name__ == "__main__":
    main()

