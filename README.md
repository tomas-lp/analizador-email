# 🛡️ Analizador Forense de Correo EML (SPF, DKIM, DMARC, Phishing y VirusTotal)

Herramienta de terminal desarrollada en Python con interfaz estilizada mediante [Rich](https://github.com/Textualize/rich) que realiza análisis forense de correos electrónicos en formato **EML** (RFC 5322 y RFC 7601), evaluando:
- Mecanismos de autenticación: **SPF**, **DKIM** y **DMARC**.
- Alineación de dominios y desvío de respuestas (**Reply-To Spoofing**).
- Detección de ataques **Homóglifos / Punycode** (IDN Spoofing).
- Detección de **Fraude del CEO / BEC** (*Business Email Compromise*).
- **Inteligencia de Amenazas con VirusTotal API v3**: Escaneo de reputación y detecciones de antivirus para todas las **URLs e IPs** encontradas en el mensaje.
- Análisis de URLs con **urlscan.io**, **crt.sh** y **WHOIS de who.is**. Las consultas de crt.sh son públicas; urlscan recibe los enlaces con visibilidad `unlisted`.

---

## 🚀 Requisitos e Instalación

1. Requiere Python 3.8+.
2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

---

## 🔐 Configuración de APIs

El programa carga las claves desde un archivo `.env` situado junto a `analizador.py`. Define allí las claves de los servicios disponibles:
```bash
VIRUSTOTAL_API_KEY="tu_api_key"
URLSCAN_API_KEY="tu_api_key"
WHOIS_API_KEY="tu_api_key"
```

También puedes definir estas variables en el entorno del proceso. VirusTotal conserva el argumento opcional `--vt-key`.

Las URLs se envían a urlscan.io con visibilidad **unlisted**; no aparecen en la búsqueda pública, aunque pueden ser visibles para investigadores y organizaciones con acceso a urlscan Pro. El programa espera hasta 30 segundos por cada tanda de resultados de urlscan; si siguen procesándose, muestra el estado pendiente y el enlace al informe. crt.sh consulta públicamente los certificados del dominio y sus subdominios. Si falta una clave de API, se informa el análisis omitido y el resto del reporte continúa.

---

## 💻 Uso

### 1. Modo Interactivo
Ejecuta el programa directamente. Mostrará la pantalla de bienvenida, detectará automáticamente todos los archivos `.eml` en la carpeta y te permitirá elegir uno por número:

```bash
python3 analizador.py
```

### 2. Modo Directo por Argumento
Analiza un archivo específico pasándolo como parámetro:

```bash
# Análisis forense, de URLs y de IoCs (según las claves configuradas):
python3 analizador.py caso_grupo_1_paqueteria.eml

# Sobrescribir la clave de VirusTotal:
python3 analizador.py caso_grupo_1_paqueteria.eml --vt-key TU_API_KEY
```

---

## 📁 Casos de Prueba Incluidos en la Carpeta

| # | Archivo EML | Escenario / Vector de Amenaza | Veredicto |
|---|---|---|---|
| 1 | `caso_grupo_1_paqueteria.eml` | Falso aviso de aduana/encomienda, SPF softfail, Reply-To divergente y enlace bit.ly | 🚨 ALTO RIESGO (Phishing) |
| 2 | `caso_grupo_2_legitimo.eml` | Confirmación de compra legítima de tienda con SPF, DKIM y DMARC alineados | ✅ BAJO RIESGO (Legítimo) |
| 3 | `caso_grupo_3_rrhh.eml` | Falso recibo de sueldo de RRHH con desalineación DMARC hacia proveedor masivo | 🚨 ALTO RIESGO (Spoofing) |
| 4 | `caso_grupo_4_homoglifo.eml` | Suplantación bancaria con dominio Punycode (`xn--...`) y caracteres cirílicos | 🚨 ALTO RIESGO (Homóglifo) |
| 5 | `caso_grupo_5_bec.eml` | Fraude del CEO (BEC) pidiendo transferencia confidencial con autenticación externa | 🚨 ALTO RIESGO (Fraude BEC) |
