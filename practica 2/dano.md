# 11. Compromiso Total de la Aplicación Descripción 

A través de la documentación API accesible en http://app2.unie/docs/, identificamos el endpoint de autenticación http://app2.unie/v2/users/login. Utilizando BurpSuite para interceptar y modificar peticiones, probamos credenciales por defecto. Explotación Petición enviada: POST /v2/users/login HTTP/1.1 Host: app2.unie Content-Type: application/json Content-Length: 56 { "email": "admin@app2.unie", "password": "admin" } Respuesta del servidor: { "message": "successfully", "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6Ijc5OTBiMmRhLTg2NWEtMTFlZi04YzJjLTAwMGMyOTY4MjFjNSJ9.7wLA68AFPXa02q6Pl46TAxwIDvvApiOWISHjbO08P-0" } La aplicación acepta las credenciales triviales admin@app2.unie / admin y devuelve un token JWT válido con privilegios de administrador. Impacto Acceso administrativo completo sin necesidad de técnicas avanzadas Compromiso de la integridad, disponibilidad y confidencialidad de todos los datos Gestión completa de usuarios y recursos Posible modificación o eliminación de información crítica Base para ataques posteriores contra otros sistemas

**1) Hashear contraseñas al crear y al actualizar**

UserService.php

En index() (línea 69), antes de create():

$passwordHash = password_hash($body['password'], PASSWORD_DEFAULT);
$create_user = $user_model->create([$name, $email, $passwordHash]);


En update() (líne 169), antes de update():

$passwordHash = password_hash($body['password'], PASSWORD_DEFAULT);
$update_user = $user_model->update([$name, $passwordHash, $user_id]);

**2) Corregir create()**

User.php → create()
Reemplazar de la línea 32–34 por:

$stm = $this->pdo->prepare("INSERT INTO users (name, email, passwd) VALUES (?, ?, ?)");
$stm->execute([$data[0], $data[1], $data[2]]);
return true;

**3) Verificar contraseña con password_verify en signIn()**

User.php → signIn()
Sustituimos la comparación de la línea 51 por:

if (password_verify($data[1], $user['passwd'])) {
  return $user['id'];
}
return false;

# 13. Vulnerabilidad en el Uso del Token Bearer
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

**Solución (práctica) en 3 niveles**

**NIVEL 1**

Nivel 1: arreglar “token infinito” y validación débil

1) Añadir 3 propiedades nuevas

private $issuer = 'app2.unie';
private $audience = 'app2.unie';
private $ttl_seconds = 900; // 15 minutos
Por qué: para poder validar emisor/destino del token y para que el token tenga caducidad (evita “token infinito”).

2) Cambios en generateJWT($data)

$now = time();

$header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);

$payload = json_encode(array_merge([
  'iss' => $this->issuer,
  'aud' => $this->audience,
  'iat' => $now,
  'nbf' => $now,
  'exp' => $now + $this->ttl_seconds,
], $data));

3) Cambios exactos validateJWT($token)

3.1) Validación de formato del token

$token = explode('.', $token);

if (count($token) !== 3) {
  return false;
}

3.2) Comparación segura de firmas

$signature = $this->signature($token[0], $token[1]);

if (!hash_equals($signature, $token[2])) {
  return false;
}

3.3) Validar expiración y claims antes de devolver usuario

$payload = json_decode($this->base64url_decode($token[1]), true);

if (!$payload) {
  return false;
}

$now = time();

// Validaciones de tiempo
if (!isset($payload['exp']) || $now >= (int)$payload['exp']) return false;
if (isset($payload['nbf']) && $now < (int)$payload['nbf']) return false;

// Validación de emisor y audiencia
if (($payload['iss'] ?? '') !== $this->issuer) return false;
if (($payload['aud'] ?? '') !== $this->audience) return false;

return (object)$payload;

**NIVEL 2**

Nivel 2: granularidad + revocación real 

1) Extender tabla users
   
ALTER TABLE users
  ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user',
  ADD COLUMN token_version INT NOT NULL DEFAULT 0;

2) Emite token con sub, role, ver

"token" => $jwt->generateJWT([
  "sub" => $user['id'],
  "role" => $user['role'],
  "ver" => $user['token_version']
])

3) Comprueba revocación

public function getTokenVersionAndRole($id)
{
  $stm = $this->pdo->prepare("SELECT token_version, role FROM users WHERE id = ?");
  $stm->execute([$id]);
  return $stm->fetch(PDO::FETCH_ASSOC) ?: false;
}

4) Revocar tokens cuando cambias password

public function bumpTokenVersion($id)
{
  $stm = $this->pdo->prepare("UPDATE users SET token_version = token_version + 1 WHERE id = ?");
  $stm->execute([$id]);
  return $stm->rowCount() > 0;
} 

**NIVEL 3**

Nivel 3: autorización por endpoint + rate limiting

if ($claims->role !== 'admin') {
  http_response_code(403);
  echo json_encode(["error" => "Forbidden"]);
  exit;
}









