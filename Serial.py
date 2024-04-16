# Made by Slam 2024
import serial
import io
import os
import subprocess
import signal
import platform
import serial.tools.list_ports

def myOs():
    return platform.system()

def port_list():
    systm = myOs()
    if systm == "Windows":
        print("You are running on Windows.")
        print("Available COM ports:")
        for port in serial.tools.list_ports.comports():
            print(port.device)
    elif systm == "Darwin":
        print("You are running on macOS.")
        for port in serial.tools.list_ports.comports():
            print(port.device)
    elif systm == "Linux":
        print("You are running on Linux.")
        for port in serial.tools.list_ports.comports():
            print(port.device)
    else:
        print("Unknow OS")

def connect(port):
    try:
        ser = serial.Serial(port, baudrate=115200)
        printf"Connecting to {puerto}")
        return ser
    except serial.SerialException as e:
        print(f"Can't connect to {puerto}: {e}")
        return None
    
def getFilename():
    try:
        filename = input("[?] Type a  filename (by default: 'capture.pcap'): ")
        if filename == "":
            filename = "capture.pcap"
        return filename
    except KeyboardInterrupt:
        print("\n[+] Closing...")
        exit()

def start_wireshark(filename):
    print("Starting up Wireshark...")
    cmd = f"tail -f -c +0 {filename} | wireshark -k -i {filename}"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    return p

def main():
    port_list()
    selected_port = input("Select the Serial Port: ")
    ser = connect(selected_port)
    if ser:
       fname = getFilename()
        try:
            counter = 0
            with open(fname, 'wb') as f:
                check = 0
                while check == 0:
                    line = ser.readline()
                    if b"<<START>>" in line:
                        check = 1
                    print("Stream started...")
                    p = start_wireshark(fname)
                    while True:
                        ch = ser.read()
                        f.write(ch)
                        f.flush()
        except KeyboardInterrupt:
            print("[+] Stopping...")
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except ProcessLookupError:
                print("Proccess stoped.")
        finally:
            ser.close()
            print("Done.")

if __name__ == "__main__":
    main()
