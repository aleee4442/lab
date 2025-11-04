Buffer Overflow
Contraseñas malas
Secretos en el código 
 
# NMAP 
Puertos abiertos:
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

Ahora que tenemos la contraseña tratamos de conectarnos pero nos da error por lo que vamos a tratar de hacer fuerza bruta con **hydra**

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

