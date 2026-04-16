
# Auditoría de Seguridad Completa: Pentesting y Hardening

**Trabajo Universitario | Seguridad Informática y Ciberseguridad en la Empresa**  
*Curso 2025/2026 - Universidad UNIE*


## Visión General del Proyecto

Este repositorio documenta un **ejercicio completo de ciberseguridad** dividido en dos fases principales, emulando el ciclo de vida real de un profesional de la seguridad:

1.  **Práctica 1 (Red Team):** Actuando como atacantes, realizamos un **pentesting** exhaustivo sobre un entorno con tres aplicaciones web (Django, PHP/API, Flask) y varios servicios de red. El objetivo era descubrir, explotar y documentar el mayor número posible de vulnerabilidades.
2.  **Práctica 2 (Blue Team):** Una vez identificadas las fallas, asumimos el rol de defensores para **mitigar todas las vulnerabilidades** encontradas e implementar medidas de seguridad adicionales, fortaleciendo el sistema sin afectar su funcionalidad.

Este proyecto es una **muestra de mi pasión por la ciberseguridad** y mi capacidad para comprender tanto el ataque como la defensa, un conjunto de habilidades que busco aplicar en mi carrera profesional.


## Estructura del Repositorio

El repositorio está organizado para reflejar claramente las dos fases del proyecto:

-   **`/practica 1/`**
    -   `Informe_Final.md`: El análisis completo de la fase de ataque. Contiene la metodología, hallazgos, vectores de explotación y el impacto de cada vulnerabilidad.
    -   `photos/`: Evidencias gráficas del proceso de reconocimiento (escaneos `nmap`) y de la explotación de fallos (RCE, SQLi, etc.).
    -   `bruteforce.py`: Script realizado en python para realizar un ataque de fuerza bruta con el archivo rockyou.txt para sacar la contraseña admin de la pagina web

-   **`/practica 2/`**
    -   `Práctica2_Informe_final.md`: El informe de la fase defensiva. Detalla cada corrección aplicada y las nuevas medidas de seguridad implementadas.
    -   `photos/`: Evidencias gráficas del proceso de solución de vulnerabilidades (código) y de la isntalación del firewall.

-   **`README.md`**: Este archivo, que sirve como punto de entrada y resumen ejecutivo del proyecto.


## Fase 1: Análisis de Vulnerabilidades (Pentesting)

En esta fase, emulamos las tácticas, técnicas y procedimientos (TTPs) de un atacante real. Se siguió una metodología estructurada:

1.  **Reconocimiento:** Escaneo de puertos y servicios con `nmap`.
2.  **Enumeración:** Análisis detallado de cada servicio (web, FTP, SSH, DB).
3.  **Explotación:** Identificación y explotación práctica de vulnerabilidades.

### Principales Vulnerabilidades Encontradas (Nivel Crítico y Alto)

| Vulnerabilidad | Aplicación/Servicio | Impacto |
| :--- | :--- | :--- |
| **Exposición de Backups (Código Fuente)** | Puerto 9001 (SimpleHTTPServer) | Filtración total del código, credenciales hardcodeadas y esquemas de BD. |
| **RCE vía Deserialización Insegura (Python Pickle)** | App1 (Django) | Ejecución remota de comandos en el servidor. |
| **SQL Injection** | App2 (PHP) y App3 (Flask) | Bypass de autenticación y extracción completa de datos. |
| **PHP Type Juggling** | App2 (PHP) | Bypass de autenticación en el login. |
| **Server-Side Template Injection (SSTI)** | App3 (Flask) | Ejecución remota de código (RCE) en el servidor. |
| **Buffer Overflow + Format String** | Puerto 5555 (Binario C) | Ejecución de código arbitrario con privilegios de `root`. |
| **Permisos `sudo` Mal Configurados** | Sistema Ubuntu (usuario `user`) | Escalada de privilegios inmediata a `root` (control total del sistema). |
| **Contraseñas débiles/predeterminadas** | App1, App2, App3, MySQL | Compromiso total de las aplicaciones y bases de datos. |
| **Claves Secretas Expuestas** | App1, App2, App3 | Falsificación de tokens de sesión y bypass de protecciones CSRF. |
| **Directory Listing Habilitado** | App1, App2, App3 | Acceso público a archivos de usuarios y configuración. |

**El informe completo de esta fase incluye la metodología paso a paso, los comandos utilizados y las evidencias de explotación.**

## Fase 2: Mitigación y Hardening

Tras el análisis, implementamos un plan de corrección completo para asegurar el entorno. Las acciones clave fueron:

-   **Correcciones Directas:**
    -   **Configuración Segura:** Activación de `HttpOnly`, `Secure` y `SameSite` en cookies; establecimiento de `SESSION_TIMEOUT` (15 min).
    -   **Cifrado Total:** Implementación de **HTTPS** en Apache para todas las aplicaciones.
    -   **Adiós al Código Inseguro:** Reemplazo de `pickle` por `JSON` seguro (App1); parametrización de consultas SQL (App2/App3); eliminación de `render_template_string()` vulnerable (App3).
    -   **Gestión de Secretos:** Cambio de todas las claves secretas (`SECRET_KEY`) por contraseñas robustas y únicas.
    -   **Control de Accesos:** Restricción del panel `/admin` por IP (App1); desactivación del `directory listing`.

-   **Medidas de Defensa en Profundidad (Adicionales):**
    -   **Firewall Perimetral:** Configuración de `UFW` para permitir solo puertos esenciales (22, 80, 443, 21, 5555) y restringir el crítico puerto 9001 a `localhost`.
    -   **Hardening de Servicios:** Configuración de MariaDB para escuchar solo en `127.0.0.1`.
    -   **Monitorización y Logging:** Centralización de logs (Apache, sistema, aplicaciones) usando **Elasticsearch, Logstash, Filebeat y Grafana (ELK Stack)**. Se implementaron dashboards y alertas para detectar intentos de SQLi, SSTI y fuerza bruta.
    -   **Plan de Recuperación (Backups):** Script automático (vía `cron`) que realiza copias de seguridad diarias, semanales y mensuales del código, las bases de datos y las configuraciones, con verificación de integridad.


## Habilidades y Tecnologías Demostradas

Este proyecto me ha permitido aplicar y consolidar conocimientos en:

-   **Pentesting:** `nmap`, `Burp Suite`, `GDB`, `netcat`.
-   **Vulnerabilidades Web:** OWASP Top 10 (SQLi, SSTI, RCE, Cryptographic Failures, Broken Access Control).
-   **Análisis de Binarios:** Identificación de Buffer Overflows y Format Strings.
-   **Hardening de Linux:** Gestión de permisos (`sudo`), configuración de firewall (`UFW`), servicios (`systemd`).
-   **Administración de Servidores:** Apache (SSL/TLS, VirtualHosts), MySQL/MariaDB.
-   **Monitorización y Logging:** ELK Stack (Elasticsearch, Logstash, Kibana/Grafana), `Filebeat`.
-   **Lenguajes y Frameworks:** Django (Python), Flask (Python), PHP, SQL.
-   **Automatización y Backup:** Scripting en Bash, `cron`, `gzip`.


## ¿Por qué este proyecto es relevante para mi carrera?

-   **Muestra el ciclo de vida completo de la seguridad:** No solo sé encontrar fallos, sino que también sé cómo solucionarlos y construir defensas sólidas.
-   **Profundidad técnica:** El trabajo cubre vulnerabilidades que van desde el nivel de aplicación (RCE, SQLi) hasta el nivel de sistema (Buffer Overflow, escalada de privilegios).
-   **Visión profesional:** Implementar monitorización (ELK) y un plan de backup demuestra que entiendo que la seguridad es un proceso continuo, no un evento puntual.
-   **Documentación clara y rigurosa:** He preparado informes detallados, estructurados y con evidencias, imitando la calidad requerida en un entorno de consultoría o auditoría.

**Estoy buscando activamente oportunidades para iniciar mi carrera en ciberseguridad. Este repositorio es una muestra de mi dedicación, capacidad de aprendizaje y enfoque práctico.**

## Licencia

Este proyecto es de carácter educativo y ha sido desarrollado como parte de un trabajo universitario.

**Alejandro Gonzalo Millón, Daniel Relloso Orcajo, Daniel Willson Pastor**
