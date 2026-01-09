11. Compromiso Total de la Aplicación Descripción A través de la documentación API accesible en http://app2.unie/docs/, identificamos el endpoint de autenticación http://app2.unie/v2/users/login. Utilizando BurpSuite para interceptar y modificar peticiones, probamos credenciales por defecto. Explotación Petición enviada: POST /v2/users/login HTTP/1.1 Host: app2.unie Content-Type: application/json Content-Length: 56 { "email": "admin@app2.unie", "password": "admin" } Respuesta del servidor: { "message": "successfully", "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0" } La aplicación acepta las credenciales triviales admin@app2.unie / admin y devuelve un token JWT válido con privilegios de administrador. Impacto Acceso administrativo completo sin necesidad de técnicas avanzadas Compromiso de la integridad, disponibilidad y confidencialidad de todos los datos Gestión completa de usuarios y recursos Posible modificación o eliminación de información crítica Base para ataques posteriores contra otros sistemas

1) Hashear contraseñas al crear y al actualizar

UserService.php

En index() (línea 69), antes de create():

$passwordHash = password_hash($body['password'], PASSWORD_DEFAULT);
$create_user = $user_model->create([$name, $email, $passwordHash]);


En update() (líne 169), antes de update():

$passwordHash = password_hash($body['password'], PASSWORD_DEFAULT);
$update_user = $user_model->update([$name, $passwordHash, $user_id]);

2) Corregir create() 

User.php → create()
Reemplazar de la línea 32–34 por:

$stm = $this->pdo->prepare("INSERT INTO users (name, email, passwd) VALUES (?, ?, ?)");
$stm->execute([$data[0], $data[1], $data[2]]);
return true;

3) Verificar contraseña con password_verify en signIn()

User.php → signIn()
Sustituimos la comparación de la línea 51 por:

if (password_verify($data[1], $user['passwd'])) {
  return $user['id'];
}
return false;

13. Vulnerabilidad en el Uso del Token Bearer
Descripción
Una vez obtenido el token JWT mediante login (ver vulnerabilidad de compromiso total), comprobamos que añadiendo la cabecera de autorización es posible acceder a endpoints sensibles sin controles adicionales:

Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0
Con este token podemos acceder a:

http://app2.unie/v2/users/ - Lista completa de usuarios
http://app2.unie/v2/books/ - Información de todos los recursos
Análisis
El problema no es el uso de JWT en sí, sino que:

Sin granularidad de permisos: El token no parece tener scopes o roles diferenciados
Privilegios excesivos: Un solo token da acceso a todo
Sin rate limiting: No hay límites de peticiones por token
Sin expiración visible: El token parece válido indefinidamente
Sin rotación: No hay mecanismo de refresh tokens
Impacto
Acceso masivo a datos: Con un token comprometido se accede a toda la información
Imposibilidad de revocar accesos específicos: No hay control granular
Escalada de privilegios: Si un token básico es comprometido, proporciona acceso total
Exfiltración facilitada: Un atacante puede automatizar la extracción de toda la base de datos
Ausencia de auditoría: Dificulta rastrear qué acciones realizó cada token

