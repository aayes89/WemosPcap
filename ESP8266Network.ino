#include <ESP8266WiFi.h>

// Referencia: https://www.acrylicwifi.com/blog/pcap-wifi-captura-almacenamiento-trafico-wireless-windows/
struct pcap_hdr {
  uint32_t magic_number;  // Numero mágico 0xA1B2C3D4
  uint16_t version_major;  // Número de versión Mayor (ej.: 2)
  uint16_t version_minor;  // Número de versión Menor (ej.: 4)
  uint32_t thisdump_ts_sec; // Marca de tiempo de volcado (segundos)
  uint32_t thisdump_ts_usec; // Marca de tiempo de volcado (microsegundos)
  uint32_t roundup;  // Cantidad para redondear las longitudes de los paquetes 
  uint32_t sig_nets;  // Firma de la red (ej.: Ethernet)
} __attribute__((packed));

struct pcap_pkthdr {
  uint32_t ts_sec;  // Marca de tiempo en segundos
  uint32_t ts_usec;  // Marca de tiempo en microsegundos
  uint32_t caplen;  // Longitud de captura (tamaño actual del paquete)
  uint32_t len;  // Longitud de captura original (puede estar truncada)
} __attribute__((packed));

const char *ssidEstacion = "ap_essid";
const char *passwordEstacion = "ap_password";
unsigned int channel = 1;

void promisc_cb(uint8_t *buf, uint16_t len) {
  // Verificar que el paquete sea lo suficientemente largo para contener el encabezado TCP
  if (len < 20) {
    return; // Ignorar paquetes demasiado cortos para ser TCP
  }
  
  // Analizar los campos del encabezado TCP
  // Referencia: https://es.wikipedia.org/wiki/Segmento_TCP
  uint16_t puertoOrigen = (buf[0] << 8) | buf[1];
  uint16_t puertoDestino = (buf[2] << 8) | buf[3];
  uint32_t numeroSecuencia = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
  uint32_t numeroAcuseRecibo = (buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
  uint8_t longitudEncabezado = (buf[12] >> 4) * 4;
  uint8_t reservados = ((buf[12] & 0x0F) >> 1);
  bool flagURG = (buf[13] & 0x20) != 0;
  bool flagACK = (buf[13] & 0x10) != 0;
  bool flagPSH = (buf[13] & 0x08) != 0;
  bool flagRST = (buf[13] & 0x04) != 0;
  bool flagSYN = (buf[13] & 0x02) != 0;
  bool flagFIN = (buf[13] & 0x01) != 0;
  uint16_t ventanaRecepcion = (buf[14] << 8) | buf[15];
  uint16_t checksum = (buf[16] << 8) | buf[17];
  uint16_t punteroUrgente = (buf[18] << 8) | buf[19];
  
  Serial.println("------ Nuevo paquete TCP ------");
  Serial.printf("Puerto de origen: %d\n", puertoOrigen);
  Serial.printf("Puerto de destino: %d\n", puertoDestino);
  Serial.printf("Número de secuencia: %lu\n", numeroSecuencia);
  Serial.printf("Número de acuse de recibo: %lu\n", numeroAcuseRecibo);
  Serial.printf("Longitud del encabezado: %d bytes\n", longitudEncabezado);
  Serial.printf("Reservados: %d\n", reservados);
  Serial.printf("URG: %s\n", flagURG ? "Sí" : "No");
  Serial.printf("ACK: %s\n", flagACK ? "Sí" : "No");
  Serial.printf("PSH: %s\n", flagPSH ? "Sí" : "No");
  Serial.printf("RST: %s\n", flagRST ? "Sí" : "No");
  Serial.printf("SYN: %s\n", flagSYN ? "Sí" : "No");
  Serial.printf("FIN: %s\n", flagFIN ? "Sí" : "No");
  Serial.printf("Ventana de recepción: %d\n", ventanaRecepcion);
  Serial.printf("Checksum: 0x%04X\n", checksum);
  Serial.printf("Puntero urgente: %d\n", punteroUrgente);
  
  // Analizar los datos después del encabezado TCP para identificar el protocolo de la capa de aplicación
  if (len > longitudEncabezado) {
    uint8_t *datos = buf + longitudEncabezado;
    uint8_t protocoloIP = datos[0];
    // Intentar identificar otros protocolos de aplicación
    if (len > longitudEncabezado + 3) {
      // Extraer direcciones IP
    uint8_t ipOrigen[4] = {datos[0], datos[1], datos[2], datos[3]};
    uint8_t ipDestino[4] = {datos[4], datos[5], datos[6], datos[7]};

    // Convertir bytes a enteros e imprimir direcciones IP
    uint32_t ipOrigenInt = (ipOrigen[0] << 24) | (ipOrigen[1] << 16) | (ipOrigen[2] << 8) | ipOrigen[3];
    uint32_t ipDestinoInt = (ipDestino[0] << 24) | (ipDestino[1] << 16) | (ipDestino[2] << 8) | ipDestino[3];
    Serial.printf("IP Origen: %d.%d.%d.%d\n", ipOrigenInt >> 24, (ipOrigenInt >> 16) & 0xFF, (ipOrigenInt >> 8) & 0xFF, ipOrigenInt & 0xFF);
    Serial.printf("IP Destino: %d.%d.%d.%d\n", ipDestinoInt >> 24, (ipDestinoInt >> 16) & 0xFF, (ipDestinoInt >> 8) & 0xFF, ipDestinoInt & 0xFF);
    
    // Obtener protocolos de la capa
      if(protocoloIP == 1){
        Serial.println("Protocolo: ICMP");
      }else if(protocoloIP == 17){
        if(datos[1] == 53){
          Serial.println("Protocolo: DNS");
          return;
        }else if((datos[1] == 20 || datos[1] == 21) && datos[2] == 0){
          Serial.println("Protocolo: FTP");
          return;
        }
      }else if (protocoloIP == 6 && (datos[13] & 0x02) == 0x02) { // Bandera SYN establecida
        Serial.println("Protocolo: FTP");
        return;
      }else if (datos[0] == 0x16 && datos[1] == 0x03 && datos[2] <= 0x03) {
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
    Serial.println("\n------ Fin del paquete TCP ------");
  }
}


void promiscue(uint8_t *buf, uint16_t len) {
  for (int i = 0; i < len; i++) {
    Serial.printf("%02x ", buf[i]); // Imprime cada byte del paquete en formato hexadecimal
  }
  Serial.println(); // Imprime una nueva línea para separar cada paquete
}

void send_pcap_packet(uint8_t *data, uint16_t len) {
  // Crea la cabecera pcap
  static pcap_hdr pcap_header;  // Para inicialización de una vez declara pcap_hdr 
  static bool header_sent = false;  // Bandera de chequeo de una vez

  // Inicializa la cabecera pcap
  if (!header_sent) {
    pcap_header.magic_number = 0xA1B2C3D4;
    pcap_header.version_major = 2;
    pcap_header.version_minor = 4;
    pcap_header.thisdump_ts_sec = get_timestamp_seconds();
    pcap_header.thisdump_ts_usec = get_timestamp_microseconds();
    pcap_header.roundup = 0;  // Opcional para la transmisión por serial
    pcap_header.sig_nets = 1;  // Se asume que la red es Ethernet (cambiar en caso contrario)
    header_sent = true;
    Serial.write((uint8_t *)&pcap_header, sizeof(pcap_header));
  }

  // Crea la cabecera pcap
  pcap_pkthdr pkthdr;
  pkthdr.ts_sec = get_timestamp_seconds();
  pkthdr.ts_usec = get_timestamp_microseconds();
  pkthdr.caplen = len;
  pkthdr.len = len;

  // Envia la cabecera pcap
  Serial.write((uint8_t *)&pkthdr, sizeof(pkthdr));

  // Envia los datos
  Serial.write(data, len);
}

void close_pcap_file() {
  // Completar si lo deseas (opcional)
}

unsigned long get_timestamp_seconds() {
  // Reemplazar con el tiempo que se ajuste a tus necesidades en caso de requerirlo
  unsigned long milliseconds = millis();
  return milliseconds / 1000;
}

unsigned long get_timestamp_microseconds() {
  // Reemplazar con el tiempo que se ajuste a tus necesidades en caso de requerirlo
  unsigned long milliseconds = millis();
  return milliseconds % 1000 * 1000;
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
  Serial.println("1. Modo promiscuo sin formato");
  Serial.println("2. Modo promiscuo filtrado");
  Serial.println("3. Enviar a Wireshark por Serial");
  
  // Espera por el ingreso de datos
  while (!Serial.available()) { 
    delay(100); // Cada 100 milisegundos espera por datos 
  }

  // Lee los datos Serial
  int opc = Serial.read() - '0'; 
  if(opc == 1){
    wifi_set_promiscuous_rx_cb(promiscue);
  }else if(opc == 2){
    wifi_set_promiscuous_rx_cb(promisc_cb);
  }else if(opc == 3){
    wifi_set_promiscuous_rx_cb(send_pcap_packet);
  }else Serial.println("Opcion incorrecta");
}

void loop() {
    if (++channel == 15){ 
      channel = 1; // Canales del 1 al 14
    }
    wifi_set_channel(channel);
    delay(1);
}
