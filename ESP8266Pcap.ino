// Made by Slam 2024
#include <ESP8266WiFi.h>

const char *essid = "ESSID";
const char *passwd = "essid_password";
unsigned int channel = 1;

void promisc_filtered(uint8_t *buf, uint16_t len) {
  signed power;
  if (len == 12) {
    power = buf[0]; // rssi
  } else if (len == 128) {
    power = buf[0]; // rssi
  } else {
    power = buf[0]; // rssi
  }

  if ((buf[12] == 0x88) || (buf[12] == 0x40) || (buf[12] == 0x94) || (buf[12] == 0xa4) || (buf[12] == 0xb4) || (buf[12] == 0x08)) {
    for (int i = 0; i < 6; i++) {
      Serial.printf("%02x:", buf[22 + i]); // MAC address
    }
    Serial.printf("%02x  ", buf[22 + 5]); // MAC address
    Serial.printf("%i\n", int8_t(buf[0])); // Signal strength
  }
}

void promisc_mode(uint8_t *buf, uint16_t len) {
  for (int i = 0; i < len; i++) {
    Serial.printf("%02x ", buf[i]); // byte to hexadecimal
  }
  Serial.println(); // new line
}


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(essid, passwd);
  Serial.print("\Connecting to ");
  Serial.print(essid);
   
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("Connected!!!");

  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channel);
  wifi_promiscuous_enable(1);
  Serial.println("Select mode: ");
  Serial.println("1. Promiscuous mode");
  Serial.println("2. Promiscuous filtered");
  
  int opc = 1;//Serial.read();
  if(opc == 1){
    wifi_set_promiscuous_rx_cb(promisc_mode);
  }else if(opc == 2){
    wifi_set_promiscuous_rx_cb(promisc_filtered);
  }
 
}

void loop() {
  channel = 1;
  while (true) {
    if (++channel == 15) break; // Only scan channels 1 to 14
    wifi_set_channel(channel);
    delay(1); // Critical processing timeslice for NONOS SDK! No delay(0) yield()
  }
}
