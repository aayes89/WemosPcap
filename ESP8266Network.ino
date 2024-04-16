#include <ESP8266WiFi.h>

const char *ssidEstacion = "essid";
const char *passwordEstacion = "password";
unsigned int channel = 1;

void promisc_cb(uint8_t *buf, uint16_t len) {
  // Verificar que el paquete sea lo suficientemente largo para contener el encabezado TCP
  if (len < 20) {
    return; // Ignorar paquetes demasiado cortos para ser TCP
  }
  
  // Analizar los campos del encabezado TCP
  uint16_t puertoOrigen = (buf[0] << 8) | buf[1];
  uint16_t puertoDestino = (buf[2] << 8) | buf[3];
  uint32_t numeroSecuencia = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
  uint32_t numeroAcuseRecibo = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
  uint8_t longitudEncabezado = (buf[12] >> 4) * 4; // Convertir la longitud del encabezado de palabras a bytes
  bool flagSYN = (buf[13] & 0x02) != 0;
  bool flagACK = (buf[13] & 0x10) != 0;
  bool flagFIN = (buf[13] & 0x01) != 0;
  uint16_t ventanaRecepcion = (buf[14] << 8) | buf[15];
  uint16_t checksum = (buf[16] << 8) | buf[17];
  uint16_t punteroUrgente = (buf[18] << 8) | buf[19];
  
  // Imprimir la información del encabezado TCP
  Serial.println("------ Nuevo paquete TCP ------");
  Serial.printf("Puerto de origen: %d\n", puertoOrigen);
  Serial.printf("Puerto de destino: %d\n", puertoDestino);
  Serial.printf("Número de secuencia: %lu\n", numeroSecuencia);
  Serial.printf("Número de acuse de recibo: %lu\n", numeroAcuseRecibo);
  Serial.printf("Longitud del encabezado: %d bytes\n", longitudEncabezado);
  Serial.printf("SYN: %s\n", flagSYN ? "Sí" : "No");
  Serial.printf("ACK: %s\n", flagACK ? "Sí" : "No");
  Serial.printf("FIN: %s\n", flagFIN ? "Sí" : "No");
  Serial.printf("Ventana de recepción: %d\n", ventanaRecepcion);
  Serial.printf("Checksum: 0x%04X\n", checksum);
  Serial.printf("Puntero urgente: %d\n", punteroUrgente);
  
  // Analizar los datos después del encabezado TCP para identificar el protocolo de la capa de aplicación
  if (len > longitudEncabezado) {
    uint8_t *datos = buf + longitudEncabezado;
    // Intentar identificar otros protocolos de aplicación
    if (len > longitudEncabezado + 3) {
      if (datos[0] == 0x16 && datos[1] == 0x03 && datos[2] <= 0x03) {
        Serial.println("Protocolo: TLS/SSL");
        return;
      } else if (datos[0] == 0x48 && datos[1] == 0x54 && datos[2] == 0x54 && datos[3] == 0x50) {
        Serial.println("Protocolo: HTTP");
        return;
      } else if (datos[0] == 0x47 && datos[1] == 0x45 && datos[2] == 0x54 && datos[3] == 0x20) {
        Serial.println("Protocolo: GET");
        return;
      } else if (datos[0] == 0x50 && datos[1] == 0x4F && datos[2] == 0x53 && datos[3] == 0x54) {
        Serial.println("Protocolo: POST");
        return;
      }
    }
    // Si no se reconoce el protocolo, imprimir los datos del paquete TCP en formato hexadecimal
    Serial.println("Protocolo: Desconocido");
    Serial.println("Datos del paquete TCP:");
    for (int i = longitudEncabezado; i < len; i++) {
      Serial.printf("%02X ", buf[i]); // Mostrar cada byte de datos en formato hexadecimal
    }
    Serial.println();
  }
}


void promiscue(uint8_t *buf, uint16_t len) {
  for (int i = 0; i < len; i++) {
    Serial.printf("%02x ", buf[i]); // Imprime cada byte del paquete en formato hexadecimal
  }
  Serial.println(); // Imprime una nueva línea para separar cada paquete
}


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssidEstacion, passwordEstacion);
  Serial.print("\nConectando a ");
  Serial.print(ssidEstacion);
   
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("Conectado a la red WiFi");

  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channel);
  wifi_promiscuous_enable(1);
  Serial.println("Seleccione el modo de captura: ");
  Serial.println("1. Modo promiscuo");
  Serial.println("2. Modo promiscuo filtrado");
  //if(Serial.available()){
  int opc = 2;//Serial.read();
  if(opc == 1){
    wifi_set_promiscuous_rx_cb(promiscue);
  }else if(opc == 2){
    wifi_set_promiscuous_rx_cb(promisc_cb);
  }else Serial.println("Opcion incorrecta");
  //}
}

void loop() {
  channel = 1;
  while (true) {
    if (++channel == 15) break; // Only scan channels 1 to 14
    wifi_set_channel(channel);
    delay(1); // Critical processing timeslice for NONOS SDK! No delay(0) yield()
  }
}
