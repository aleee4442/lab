**App1**

La app1 es un portal de inicio de sesión de donde cuelgan varios bloques de texto (default) con botones aparentemente sin utilidad.

He conseguido iniciar sesión con user / user tal y como marca la guía de la práctica 
He conseguido iniciar sesión con admin / admin (no aparecer en la guía de la práctica)
He creado un usuario nuevo con la opción de registrar dano / ****** 

Al iniciar sesión puedes acceder a un nuevo apartado de la pagina donde puedes subir archivos, imagenes, .txt, etc

Debido a la simpleza del usuario y contraseña admin / admin he logrado acceder a http://app1.unie/admin/ y una vez allí repitiendo las credenciales he conseguido acceder al panel de administración

He conseguido acceder a http://app1.unie/static/ donde parece que esta alojado una carpeta con toda la información de la web, desde ahí he podido (sin iniciar sesión) todos los archivos que se habían subido desde múltiples cuentas 

**QUIERO REVISAR SI AL INICIAR SESIÓN MANTIENE LA MISMA COOKIE**
**REVISAR APP1 CON BURPSUITE (VER PERFIL)** Revisar la encriptación del token 

**App2**

Se puede acceder a http://app2.unie/app/
Tras acceder a http://app2.unie/docs/ en la documentación vemos que podemos intentar iniciar sesión desde http://app2.unie/v2/users/login para ellos usamos burpsuite para interceptar el tráfico. Si usamos:

""
Content-Type: application/json
Content-Length: 56

{
	"email":"admin@app2.unie",
	"password":"admin"
}
""

Conseguimos esta respuesta: El token de sesión 

"message":"successfully",
"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0"

Gracias al token de sesión y el uso de la cabecera siguiente conseguimos acceder a v2/users/ y v2/books/

Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0

**PISTAS**

App2 hay un fallo llamado php type juggling 
App1 o App3 hay dos fallos SSTI y RCE UNPICKLE


