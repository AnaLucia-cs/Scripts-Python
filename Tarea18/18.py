import sys
import requests
import time
import getpass
import os
import logging
import csv

logging.basicConfig(
    filename="registro.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
if len(sys.argv) != 2:
    print("Uso: python verificar_correo.py correo@example.com")
    sys.exit(1)
correo = sys.argv[1]
try:
    with open("apikey.txt", "r") as archivo:
        api_key = archivo.read().strip()
except FileNotFoundError:
    if not os.path.exists("apikey.txt"):
        print("🔐 No se encontró el archivo apikey.txt.")
        clave = getpass.getpass("Ingresa tu API key: ")
        with open("apikey.txt", "w") as archivo:
            archivo.write(clave.strip())
        with open("apikey.txt", "r") as archivo:
            api_key = archivo.read().strip()
url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
headers = {
    "hibp-api-key": api_key,
    "user-agent": "PythonScript"
}
response = requests.get(url, headers=headers)
with open("reporte.csv", "w", newline='', encoding="utf-8") as archivo_csv:
    writer = csv.writer(archivo_csv)
    writer.writerow(["Titulo", "Dominio", "Fecha de Brecha",
                     "Datos Comprometidos", "Verificada", "Sensible"])
    if response.status_code == 200:
        brechas = response.json()
        logging.info(f"Consulta exitosa para {correo}. \
Brechas encontradas: {len(brechas)}")
        print(f"\nLa cuenta {correo} ha sido comprometida en \
{len(brechas)} brechas.")
        print("Mostrando detalles de las primeras 3 brechas:\n")
        for i, brecha in enumerate(brechas[:3]):
            nombre = brecha['Name']
            detalle_url = f"https://haveibeenpwned.com/api/v3/breach/{nombre}"
            detalle_resp = requests.get(detalle_url, headers=headers)
            if detalle_resp.status_code == 200:
                detalle = detalle_resp.json()
                print(f"Brecha {i+1}: {detalle.get('Title')}")
                print(f"Dominio: {detalle.get('Domain')}")
                print(f"Fecha de brecha: {detalle.get('BreachDate')}")
                print(f"Fecha registrada: {detalle.get('AddedDate')}")
                print(f"Datos comprometidos: \
{', '.join(detalle.get('DataClasses', []))}")
                print(f"Descripción: {detalle.get('Description')[:300]}...\n")
                print("-" * 60)
                t = detalle.get('Title')
                d = detalle.get('Domain')
                f = detalle.get('AddedDate')
                da = ', '.join(detalle.get('DataClasses', []))
                v = detalle.get('IsVerified')
                s = detalle.get('IsSensitive')
                writer.writerow([t, d, f, da, v, s])
            else:
                print(f"No se pudo obtener detalles de la brecha: {nombre}")
            if i < 2:
                print("Esperando 10 segundos \
antes de la siguiente consulta...\n")
                time.sleep(10)
    elif response.status_code == 404:
        print(f"La cuenta {correo} no aparece en ninguna brecha conocida.")
        logging.info(f"Consulta exitosa para {correo}. \
No se encontraron brechas.")
    elif response.status_code == 401:
        logging.error("Error 401: API key inválida.")
        print("Error de autenticación: revisa tu API key.")
    else:
        print(f"Error inesperado. Código de estado: {response.status_code}")
        logging.error(f"Error inesperado. \
Código de estado: {response.status_code}")
