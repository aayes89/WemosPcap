# WemosPcap
ESP8266 network analyzer

Using a Wemos D1 with ESP8266 to capture raw or filtered packets from a wireless network.

# Whats in the Box
* ESP8266Network.ino -> can filter TCP packets from the Wifi station. Actually (HTTP, SSH/TLS, GET, POST)
* ESP8266Pcap.ino -> capture raw packets without filter. An intent to send to Wireshark through Serial connection. 
* A Python script to capture the data from the serial port regardless of the operating system, this script generates a .pcap file that can be used by Wireshark.

# TODO
* Add pcap support
* Send the data obtained in pcap standard via serial port
