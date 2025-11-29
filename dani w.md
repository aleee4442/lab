<<<<<<< HEAD
Buffer Overflow
Contraseñas malas
Secretos en el código 
 
# NMAP 
**Puertos abiertos**:
```
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
5555/tcp open  freeciv
9001/tcp open  tor-orport
```  

información importante sobre los 
```
PORT      STATE  SERVICE VERSION
21/tcp    open   ftp     vsftpd (broken: both local and anonymous access disabled!)

se necesita usuario ya que el acceso anónimo está deshabilitado 

22/tcp    open   ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a1:a0:86:5d:7c:7f:4e:f4:ab:ca:90:0d:49:89:e4:7c (ECDSA)
|_  256 30:c4:82:38:86:3e:08:3e:87:5c:a8:08:f6:8d:fe:e1 (ED25519)

tenemos la ssh key pero ssh es bastante jodido de crackear, revisar exploit con la versión
  
80/tcp    open   http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)

página web

3306/tcp  open   mysql   MariaDB 10.3.23 or earlier (unauthorized)
base de datos con inicio de sesión

9001/tcp  open   http    SimpleHTTPServer 0.6 (Python 3.13.0)
|_http-server-header: SimpleHTTP/0.6 Python/3.13.0
|_http-title: Directory listing for /

pagina web 2

55555/tcp closed unknown
no info revisar puerto
```

=======
Buffer Overflow
Contraseñas malas
Secretos en el código 
 
# NMAP 
**Puertos abiertos**:
```
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
5555/tcp open  freeciv
9001/tcp open  tor-orport
```  

información importante sobre los 
```
PORT      STATE  SERVICE VERSION
21/tcp    open   ftp     vsftpd (broken: both local and anonymous access disabled!)

se necesita usuario ya que el acceso anónimo está deshabilitado 

22/tcp    open   ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a1:a0:86:5d:7c:7f:4e:f4:ab:ca:90:0d:49:89:e4:7c (ECDSA)
|_  256 30:c4:82:38:86:3e:08:3e:87:5c:a8:08:f6:8d:fe:e1 (ED25519)

tenemos la ssh key pero ssh es bastante jodido de crackear, revisar exploit con la versión
  
80/tcp    open   http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)

página web

3306/tcp  open   mysql   MariaDB 10.3.23 or earlier (unauthorized)
base de datos con inicio de sesión

9001/tcp  open   http    SimpleHTTPServer 0.6 (Python 3.13.0)
|_http-server-header: SimpleHTTP/0.6 Python/3.13.0
|_http-title: Directory listing for /

pagina web 2

55555/tcp closed unknown
no info revisar puerto
```

```
/opp
/html
tener burpsuite activado

app2 es una api, que hay que mandar como json. iniciar sesion antes. en app 2 hay un fallo que se llama php type juggling
app 3, tenemos ssti
app 1 tenemos rce unpickle
```

---

# Vulnerabilidad 1: Exposición Pública de Copias de Seguridad del Código Fuente

## Descripción

Durante el reconocimiento inicial del objetivo, descubrimos que el servidor web alojado en el puerto 9001 (mediante un servidor SimpleHTTPServer de Python) servía una lista de directorios sin protección de autenticación. En dicha lista aparecían varios archivos con nombres reveladores, entre ellos `backup_app1.tar.gz`.

Al descargar y analizar este archivo, obtuvimos una copia completa del código fuente de la aplicación web "App1", incluyendo archivos de configuración sensibles. Esto constituye una vulnerabilidad crítica de configuración que permite a cualquier atacante obtener información privilegiada sin necesidad de autenticación.

## Explotación Paso a Paso

### 1. Descarga del archivo de respaldo

Utilizamos `wget` para descargar el archivo directamente desde el servidor web:

```bash
wget http://192.168.88.131:9001/backup_app1.tar.gz
```

**¿Por qué?**  
`wget` es una herramienta estándar en entornos Linux para descargar archivos mediante HTTP/HTTPS. Al acceder a la URL del puerto 9001, el servidor mostraba una lista de archivos descargables, y este archivo era uno de ellos, lo que indica que no hay restricciones de acceso.

### 2. Extracción del archivo comprimido

El archivo descargado estaba comprimido en formato `.tar.gz`. Lo descomprimimos con:

```bash
tar -xzf backup_app1.tar.gz
```

**¿Por qué?**  
El comando `tar -xzf` descomprime archivos `.tar.gz` en Linux. La opción `-x` indica extracción, `-z` indica compresión gzip, y `-f` especifica el nombre del archivo. Tras la extracción, se creó una estructura de directorios típica de una aplicación web Django.

### 3. Navegación hasta el código fuente

Observamos que el contenido no se había extraído en una carpeta llamada `backup_app1`, sino directamente en el sistema de archivos. Detectamos una carpeta `var/www/html/app1/`, que es la ruta estándar en sistemas basados en Debian/Ubuntu para alojar aplicaciones web.

Navegamos hasta ella:

```bash
cd var/www/html/app1
```

### 4. Búsqueda de archivos de configuración sensibles

Ejecutamos comandos para localizar archivos clave:

```bash
find . -name "common.py"
```

**¿Por qué buscar `common.py`?**  
En aplicaciones Django, es común separar la configuración en módulos como `settings/common.py`, `settings/production.py`, etc. Este archivo suele contener credenciales, rutas y ajustes esenciales del entorno.

El comando devolvió la ruta:

```
./app1/settings/common.py
```

### 5. Análisis del archivo de configuración

Abrimos el archivo con `cat`:

```bash
cat ./app1/settings/common.py
```

Dentro encontramos credenciales de la base de datos en texto claro:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'app1_database',
        'USER': 'app1_user',
        'PASSWORD': 'app1_password',
        'HOST': 'localhost',
        'PORT': '',
    }
}
```

Además, observamos que la variable de depuración está desactivada por defecto, pero controlada por una variable de entorno:

```python
DEBUG = env.bool("DJANGO_DEBUG", False)
```

**¿Qué significa esto?**  
Aunque `DEBUG = False` por defecto, si la aplicación se ejecuta con `DJANGO_DEBUG=True` (por ejemplo, en un entorno de desarrollo mal configurado), la aplicación mostrará trazas de error detalladas, incluyendo rutas del sistema, variables de entorno y consultas SQL ejecutadas — una fuente de información extremadamente valiosa para un atacante.

## Impacto de la Vulnerabilidad

Esta situación permite a un atacante:

- Obtener credenciales de bases de datos sin necesidad de técnicas de fuerza bruta o inyección SQL.
- Conocer la arquitectura interna de la aplicación (estructura de carpetas, dependencias, rutas).
- Explorar lógica de negocio y encontrar nuevas vulnerabilidades (por ejemplo, lógica de autenticación defectuosa, funciones inseguras).
- Conectar directamente a la base de datos si esta acepta conexiones remotas, o usar las credenciales para ataques internos si se consigue acceso al sistema.

**Nota:** En el enunciado de la práctica se proporcionan las credenciales de la base de datos, lo que confirma que estas coinciden exactamente con las extraídas del archivo de configuración. Esto demuestra que el archivo es actual y funcional.

## Clasificación de la Vulnerabilidad

- **Tipo:** Exposición de información sensible (CWE-200)
- **Vector:** Configuración insegura del servidor web
- **Gravedad:** Crítica (CVSS ≈ 9.1)
- **Requisitos para explotar:** Solo acceso de red al puerto 9001.

## Recomendaciones

- Nunca exponer copias de seguridad en servidores web accesibles públicamente.
- Usar sistemas de control de versiones (como Git) con acceso restringido para gestionar el código.
- Almacenar credenciales en variables de entorno o gestores de secretos, y nunca en archivos de código fuente.
- Restringir el listado de directorios en servidores web (`Options -Indexes` en Apache, por ejemplo).
- Auditar periódicamente los servicios expuestos y sus contenidos.


## Conclusión

Esta vulnerabilidad, aparentemente simple, abre la puerta a toda una cadena de ataques posteriores. El hecho de que un archivo de respaldo esté accesible públicamente no solo revela credenciales, sino que también demuestra una falta de higiene en la gestión del entorno de desarrollo y despliegue, lo que suele indicar la presencia de otras debilidades.

Esta fase representa tanto la identificación como la explotación efectiva de una vulnerabilidad de configuración crítica.

> [!IMPORTANT]  
> Solo APP1

---


> [!IMPORTANT]
> Para APP2


# Vulnerabilidad 2: Exposición Pública del Esquema de Base de Datos de App2

## Descripción

Al igual que con App1, el servidor web en el puerto 9001 expone archivos de respaldo de la aplicación App2, en este caso el archivo `backup_app2.tar.gz`. Al descargarlo y analizar su contenido, descubrimos que contiene un archivo SQL (`database.sql`) que define la estructura completa de la base de datos de la aplicación.

Este archivo revela:

- La existencia de dos tablas: `users` y `books`.
- El esquema detallado de cada tabla, incluyendo tipos de datos, claves primarias y foráneas.
- Nombres exactos de columnas, como `email`, `passwd`, `user_id`, etc.

### ¿Por qué es una vulnerabilidad?

Este tipo de exposición no debería ocurrir en ningún entorno de producción. Provee a un atacante con inteligencia táctica precisa sobre el modelo de datos, lo que facilita enormemente la ejecución de ataques como:

- **Inyección SQL (SQLi):** Saber exactamente cómo se llaman las tablas y columnas permite construir payloads de inyección eficaces sin necesidad de técnicas de enumeración lentas o ruidosas.
- **Ataques dirigidos:** Saber que la columna de contraseñas se llama `passwd` (en lugar de `password`, `pwd`, etc.) reduce la incertidumbre del atacante.
- **Comprensión del modelo de negocio:** Revela relaciones entre entidades (por ejemplo, que un libro pertenece a un usuario), lo que ayuda a planificar ataques más sofisticados.

## Explotación Paso a Paso

### 1. Descarga del archivo de respaldo

```bash
wget http://192.168.88.131:9001/backup_app2.tar.gz
```

**¿Por qué?**  
El servidor SimpleHTTPServer en el puerto 9001 permite listar y descargar archivos sin autenticación. Esto es un error grave de configuración.

### 2. Extracción del archivo

```bash
tar -xzf backup_app2.tar.gz
```

**¿Por qué?**  
El archivo está comprimido en formato `.tar.gz`, común en entornos Linux para distribuir copias de seguridad.

### 3. Localización del esquema de la base de datos

```bash
find . -name "database.sql"
```

Resultado:

```
./var/www/html/app2/database.sql
```

### 4. Análisis del esquema

```bash
cat ./var/www/html/app2/database.sql
```

Salida relevante:

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

**¿Por qué es útil para un atacante?**  
Ahora sabe que puede intentar un ataque de inyección SQL en cualquier punto de entrada de App2 (por ejemplo, en un campo de login o búsqueda) usando consultas como:

```sql
' UNION SELECT id, username, email, passwd FROM users--
```

sin tener que adivinar nombres de tablas o columnas.

## Impacto

- **Gravedad:** Alta/Crítica.
- **Vector:** Configuración insegura del servidor (exposición de archivos sensibles).
- **Requisitos para explotar:** Solo acceso de red al puerto 9001.
- **Consecuencias:** Facilita la explotación de otras vulnerabilidades (como SQLi) y reduce drásticamente el tiempo y ruido de un ataque real.

## Recomendaciones

1. Nunca exponer archivos de respaldo en servidores accesibles públicamente.
2. Usar sistemas de control de versiones privados para gestionar el código fuente y los esquemas de base de datos.
3. Auditar regularmente los servicios expuestos para detectar contenido sensible.
4. Restringir el listado de directorios en servidores web (en Apache/Nginx, evita `Options Indexes`; en Python SimpleHTTPServer, no lo uses en producción).



>>>>>>> 4a1d57af2bc394f0bcf287820fef8f1f185d6397
