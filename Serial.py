# Made by Slam 2024
import serial
import io
import os
import subprocess
import signal
import platform
import serial.tools.list_ports

def detectar_sistema_operativo():
    return platform.system()

def listar_puertos():
    sistema = detectar_sistema_operativo()
    if sistema == "Windows":
        print("El código se está ejecutando en Windows.")
        print("Puertos COM disponibles:")
        for puerto in serial.tools.list_ports.comports():
            print(puerto.device)
    elif sistema == "Darwin":
        print("El código se está ejecutando en macOS.")
        for puerto in serial.tools.list_ports.comports():
            print(puerto.device)
    elif sistema == "Linux":
        print("El código se está ejecutando en Linux.")
        for puerto in serial.tools.list_ports.comports():
            print(puerto.device)
    else:
        print("Sistema operativo no reconocido.")

def conectar_puerto(puerto):
    try:
        ser = serial.Serial(puerto, baudrate=115200)
        print(f"Conectado al puerto {puerto}")
        return ser
    except serial.SerialException as e:
        print(f"No se pudo conectar al puerto {puerto}: {e}")
        return None
    
def obtener_nombre_archivo():
    try:
        nombre_archivo = input("[?] Seleccione un nombre de archivo (por defecto 'capture.pcap'): ")
        if nombre_archivo == "":
            nombre_archivo = "capture.pcap"
        return nombre_archivo
    except KeyboardInterrupt:
        print("\n[+] Saliendo...")
        exit()

def iniciar_wireshark(filename):
    print("Starting up Wireshark...")
    cmd = f"tail -f -c +0 {filename} | wireshark -k -i {filename}"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    return p

def main():
    listar_puertos()
    puerto_seleccionado = input("Seleccione el puerto al que desea conectarse: ")
    ser = conectar_puerto(puerto_seleccionado)
    if ser:
        nombre_archivo = obtener_nombre_archivo()
        try:
            counter = 0
            with open(nombre_archivo, 'wb') as f:
                check = 0
                while check == 0:
                    line = ser.readline()
                    if b"<<START>>" in line:
                        check = 1
                    print("Stream started...")
                    p = iniciar_wireshark(nombre_archivo)
                    while True:
                        ch = ser.read()
                        f.write(ch)
                        f.flush()
        except KeyboardInterrupt:
            print("[+] Stopping...")
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except ProcessLookupError:
                print("El proceso ya ha sido terminado.")
        finally:
            ser.close()
            print("Done.")

if __name__ == "__main__":
    main()
