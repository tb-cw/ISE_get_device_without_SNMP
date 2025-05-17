import requests
import json
import csv
import time
from requests.auth import HTTPBasicAuth

# Konfigurationsparameter
ISE_IP = "192.168.1.100"  # Ersetze mit der IP der Cisco ISE
USERNAME = "api_user"
PASSWORD = "password123"
CSV_FILE = "devices_without_snmp.csv"
TIMEOUT = 10  # Timeout in Sekunden für API-Requests
DEBUG = True  # Debugging aktivieren/deaktivieren

# API URL
BASE_URL = f"https://{ISE_IP}:9060/ers/config/networkdevice"
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def log_debug(message):
    """ Ausgabe von Debug-Nachrichten """
    if DEBUG:
        print(f"[DEBUG] {message}")

def get_all_network_devices():
    """ Holt alle Network Devices über Paginierung """
    devices = []
    page = 1
    size = 100  # Maximale Anzahl pro Abfrage

    while True:
        try:
            url = f"{BASE_URL}?size={size}&page={page}"
            log_debug(f"Abfrage Seite {page} mit {size} Geräten...")
            response = requests.get(
                url, 
                headers=HEADERS, 
                auth=HTTPBasicAuth(USERNAME, PASSWORD), 
                verify=False, 
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json().get("SearchResult", {}).get("resources", [])
            if not data:
                log_debug(f"Keine weiteren Geräte auf Seite {page} gefunden.")
                break

            devices.extend(data)
            log_debug(f"Seite {page}: {len(data)} Geräte gefunden.")
            page += 1

        except requests.Timeout:
            print(f"[ERROR] Timeout bei Seite {page}. Versuche erneut...")
            time.sleep(2)  # Warte 2 Sekunden und versuche erneut
        except requests.HTTPError as e:
            print(f"[ERROR] HTTP-Fehler: {e}")
            break
        except Exception as e:
            print(f"[ERROR] Fehler beim Abrufen der Network Devices: {e}")
            break

    log_debug(f"Gesamtanzahl gefundener Geräte: {len(devices)}")
    return devices

def check_snmp_config(device_id):
    """ Prüft die SNMP-Konfiguration eines Network Devices """
    try:
        device_url = f"{BASE_URL}/{device_id}"
        log_debug(f"Prüfe SNMP für Device ID {device_id}...")
        response = requests.get(
            device_url, 
            headers=HEADERS, 
            auth=HTTPBasicAuth(USERNAME, PASSWORD), 
            verify=False, 
            timeout=TIMEOUT
        )
        response.raise_for_status()

        device_data = response.json().get("NetworkDevice", {})
        device_name = device_data.get("name", "Unbekannt")
        ip_address = device_data.get("ipaddress", {}).get("ipaddress", "Unbekannt")
        device_type = device_data.get("deviceType", "Unbekannt")
        snmp_settings = device_data.get("snmpsettings", [])

        snmp_status = "SNMP konfiguriert" if snmp_settings else "Kein SNMP"
        log_debug(f"Device: {device_name}, IP: {ip_address}, SNMP: {snmp_status}")

        # Rückgabe der Gerätedaten
        return device_name, ip_address, snmp_status, device_type

    except requests.Timeout:
        print(f"[ERROR] Timeout bei SNMP-Prüfung für Device ID {device_id}.")
        return None
    except Exception as e:
        print(f"[ERROR] Fehler beim Prüfen der SNMP-Konfiguration für Device {device_id}: {e}")
        return None

def write_to_csv(data):
    """ Schreibt die Daten in eine CSV-Datei """
    try:
        with open(CSV_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Device Name", "IP Address", "SNMP Status", "Device Type"])
            writer.writerows(data)
        print(f"Erfolgreich in {CSV_FILE} geschrieben.")
    except Exception as e:
        print(f"[ERROR] Fehler beim Schreiben der CSV-Datei: {e}")

def main():
    print("Starte Abfrage der Network Devices...\n")
    devices = get_all_network_devices()

    if not devices:
        print("[INFO] Keine Network Devices gefunden.")
        return
    
    devices_without_snmp = []

    for device in devices:
        device_id = device.get("id")
        device_info = check_snmp_config(device_id)
        
        if device_info and "Kein SNMP" in device_info[2]:
            devices_without_snmp.append(device_info)

    if devices_without_snmp:
        write_to_csv(devices_without_snmp)
    else:
        print("[INFO] Alle Network Devices haben SNMP konfiguriert.")

if __name__ == "__main__":
    main()
