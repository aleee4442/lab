codigo paginas web
```
/var/www/html
```


# APP 1
## /var/www/html/app1/app1/settings/local.py

```
DEBUG = env.bool('DJANGO_DEBUG', default=False)
TEMPLATES[0]['OPTIONS']['debug'] = DEBUG
```
cambiado default=True por =False, ahora en vez de hacer el debug te sale **Server Error (500)** cuando intentas de hacer el login por http://app1.unie/users/login/
## 9001
Encontramos en `/etc/systemd/system/file-server.service` la linea que hace que se pueda acceder a traves de la web normal y no de forma local por la linea
```
ExecStart=/usr/bin/docker run --rm -v /opt/data:/data -p 0.0.0.0:9001:9001 --name file_server_container file_server_image
```
por lo que lo cambiamos por
```
ExecStart=/usr/bin/docker run --rm -v /opt/data:/data -p 127.0.0.1:9001:9001 --name file_server_container file_server_image
```
Para que solo tengamos conectividad de forma local
![[Pasted image 20251230221549.png]]

## RCE UNPICKLE
En vez de usar pickle vamos a usar json 
```python
import json, base64, os, uuid
```
Quitamos el import pickle y añadimos el json
```python
context['usernameSlug'] = base64.b64encode(pickle.dumps(request.user.username)).decode('ascii')
```








## /var/www/html/app1/app1/settings/production.py

```
SESSION_COOKIE_SECURE = True
```


## 📌 **Plan de Mitigación para Práctica 2**

### **A. Vulnerabilidades Críticas a Mitigar (según tu informe)**

| Vulnerabilidad                                     | Mitigación Propuesta                                                        |
| -------------------------------------------------- | --------------------------------------------------------------------------- |
| **Cookies inseguras (HttpOnly, Secure, SameSite)** | Configurar en settings de Django y Flask, forzar HTTPS.                     |
| **Contraseñas débiles / credenciales por defecto** | Implementar política de contraseñas fuertes, eliminar cuentas por defecto.  |
| **RCE via Pickle en App1**                         | Reemplazar `pickle.loads()` por serialización segura (JSON).                |
| **SQL Injection en App2 y App3**                   | Usar consultas parametrizadas, ORM correctamente.                           |
| **SSTI en App3**                                   | Sanitizar entradas, evitar `render_template_string()` con datos de usuario. |
| **Buffer Overflow en App5**                        | Usar funciones seguras (`fgets` en lugar de `scanf`), validar longitud.     |
| **Permisos sudo mal configurados**                 | Restringir `sudo` al mínimo necesario, usar `visudo` para editar.           |
| **Secret keys en código**                          | Mover a variables de entorno, usar `.env` o secret managers.                |
| **Tráfico sin cifrar (HTTP)**                      | Implementar HTTPS con certificados autofirmados o Let's Encrypt.            |
| **Directory listing en /static/**                  | Deshabilitar en configuración de Apache/Nginx.                              |
| **FTP anónimo**                                    | Deshabilitar acceso anónimo, usar SFTP/SSH.                                 |
| **Cronjobs inseguros**                             | Revisar que no expongan datos sensibles, limitar permisos.                  |

---

## 🛡️ **B. Medidas Adicionales para Nota de 10 (según enunciado)**

### **1. Despliegue de Firewall (UFW)**

bash

sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (redirigir a HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 21/tcp    # FTP
sudo ufw allow 5555/tcp  # App5
sudo ufw deny 9001       # Solo local (no público)
sudo ufw default deny incoming

### **2. Gestión y Monitorización de Logs (ELK Stack o Grafana + Loki)**

- Configurar logs centralizados para Apache, Django, Flask, MySQL.
    
- Alertas en caso de:
    
    - Múltiples intentos de login fallidos.
        
    - Accesos a rutas sensibles (`/admin`, `/backup`).
        
    - Patrones de SQL Injection o SSTI en logs.
        

### **3. Recuperación ante Desastres**

- Scripts de backup automáticos y encriptados.
    
- Rotación de backups (diario/semanal).
    
- Almacenamiento externo seguro (ej: S3, servidor interno).
    
- Pruebas de restauración periódicas.
    

---

## 📄 **C. Estructura del Informe de la Práctica 2**

1. **Introducción**
    
    - Objetivo: mitigar vulnerabilidades de la práctica 1.
        
    - Metodología aplicada.
        
2. **Vulnerabilidades Mitigadas**
    
    - Tabla resumen con vulnerabilidad, mitigación y evidencia (capturas de código/config).
        
    - Por cada vulnerabilidad:
        
        - Descripción breve.
            
        - Código/configuración antes/después.
            
        - Prueba de que sigue funcional.
            
3. **Medidas Adicionales Implementadas**
    
    - Firewall (captura de reglas UFW).
        
    - Sistema de logs y alertas (captura de dashboard Grafana).
        
    - Plan de backup y recuperación (script y ejemplo de backup).
        
4. **Validación de Funcionalidad**
    
    - Checklist de funcionalidades requeridas (App1, App2, App3, App4, App5, SSH, FTP, Cron, MariaDB).
        
    - Pruebas manuales/automáticas.
        
5. **Conclusión**
    
    - Resumen de mejoras.
        
    - Lecciones aprendidas.
        
6. **Anexos**
    
    - Script de entrega generado.
        
    - Configuraciones completas.
        
    - Enlaces a repositorio de código.
        

---

## 💡 **D. Consejos Clave**

- **No elimines servicios**, solo sécalos correctamente.
    
- **Usa variables de entorno** para secrets.
    
- **Documenta cada cambio** con capturas claras.
    
- **Prueba que todo sigue funcionando** tras cada modificación.
    
- **Si usas HTTPS**, redirige todo HTTP a HTTPS.
    
- **Para la entrega**, sigue el script del profesor al pie de la letra.