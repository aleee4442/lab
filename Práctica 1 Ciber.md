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

