import logging
import os
import csv
import getpass
import requests
import argparse
import time


def leer_apikey(path="apikey.txt"):
        if not os.path.exists(path):
            clave = getpass.getpass("Ingresa tu API key: ")
            with open(path, "w") as archivo:
                archivo.write(clave.strip())
        with open(path, "r") as archivo:
            return archivo.read().strip()

def obtener_argumentos():
    parser = argparse.ArgumentParser(
    description="Verifica si un correo ha sido comprometido usando la API de Have I Been Pwned.")
    parser.add_argument("correo", help="Correo electrónico a verificar")
    parser.add_argument("-o", "--output", default="reporte.csv", help="Nombre del archivo CSV de salida")
    return parser.parse_args()

def consultar_brechas(correo, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
    headers = {"hibp-api-key": api_key, "user-agent": "PythonScript"}
    return requests.get(url, headers=headers)

def consultar_brechas(correo, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
    headers = {"hibp-api-key": api_key, "user-agent": "PythonScript"}
    return requests.get(url, headers=headers)

def consultar_detalle(nombre, api_key):
    url = f"https://haveibeenpwned.com/api/v3/breach/{nombre}"
    headers = {"hibp-api-key": api_key, "user-agent": "PythonScript"}
    return requests.get(url, headers=headers)

def generar_csv(nombre_archivo, lista_detalles):
    with open(nombre_archivo, "w", newline='', encoding="utf-8") as archivo_csv:
        writer = csv.writer(archivo_csv)
        writer.writerow(["Titulo", "Dominio", "Fecha de Brecha", "Datos Comprometidos", "Verificada", "Sensible"])
        for detalle in lista_detalles:
            writer.writerow([
                detalle.get("Title"),
                detalle.get("Domain"),
                detalle.get("BreachDate"),
                ", ".join(detalle.get("DataClasses", [])),
                "Si" if detalle.get("IsVerified") else "No",
                "Si" if detalle.get("IsSensitive") else "No"
            ])

logging.basicConfig(
    filename="registro.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    args = obtener_argumentos()
    correo = args.correo
    salida = args.output
    api_key = leer_apikey()
                
    try:
        respuesta = consultar_brechas(correo, api_key)
    except Exception as e:
        logging.error(f"Error de conexión: {e}")
        exit()
        
    if respuesta.status_code == 200:
        brechas = respuesta.json()
        logging.info(f"{correo} comprometido en {len(brechas)} brechas.")
        detalles = []

        for i, brecha in enumerate(brechas[:3]):
            nombre = brecha["Name"]
            detalle_resp = consultar_detalle(nombre, api_key)
            if detalle_resp.status_code == 200:
                detalles.append(detalle_resp.json())
            else:
                logging.error(f"No se pudo obtener detalles de {nombre}. Código: {detalle_resp.status_code}")
            if i < 2:
                time.sleep(10)


        generar_csv(salida, detalles)
        print(f"Consulta completada. Revisa el archivo {salida}.")
    elif respuesta.status_code == 404:
        logging.info(f"{correo} no aparece en brechas conocidas.")
        print(f"La cuenta {correo} no aparece en ninguna brecha.")
    elif respuesta.status_code == 401:
        logging.error("API key inválida.")
        print("Error de autenticación.")
    else:
        logging.error(f"Error inesperado. Código: {respuesta.status_code}")
        print(f"Error inesperado. Código: {respuesta.status_code}")
