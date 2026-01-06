codigo paginas web
```
/var/www/html
```

# Todas las APPS
## Cambio de contraseña
Para hacer el cambio de contraseña lo vamos a hacer usando el propio django. Para cada app tenemos que ir a donde se encuentra el codigo de cada app `cd /var/www/html/app1` y ejecutamos en venv con 
```
./ENV/bin/python manage.py shell
```

una vez dentro de aqui ponemos lo siguiente (sin poner la misma contraseña en cada app)
```
from django.contrib.auth.hashers import make_password
from users.models import Person

admin_user = Person.objects.get(username='admin')  
admin_user.password = make_password('6qxK{1?D5D3Y')
admin_user.save()
```
Las contraseñas para cada app son: 
- **APP1**: 6qxK{1?D5D3Y
- **APP2**: ]2aSEja#y7d3
- **APP3**: yXv1f=$4`_33
Una vez intentas iniciar sesión ya no funciona con admin admin y tienes que poner la contrasñea establecida
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
En vez de usar pickle vamos a usar **json** 
### Quitamos el import pickle y añadimos el json
```python
import json, base64, os, uuid
```
### Cambiamos la linea 43 a:
```python
context['usernameSlug'] = base64.b64encode(json.dumps(request.user.username).encode()).decode('ascii')
```
### Cambiamos la clase ProfileView por:
```python
class ProfileView(LoginRequiredMixin, FormView, View):
    template_name = 'users/profile.html'

    def get(self, request, *args, **kwargs):
        return redirect('home')

    def post(self, request, *args, **kwargs):
        usernameSlug = request.POST.get('usernameSlug')

        try:
            username = json.loads(base64.b64decode(usernameSlug).decode('utf-8'))
            
            # Validación adicional de seguridad
            if not isinstance(username, str):
                username = "invalid_user"
                
        except (json.JSONDecodeError, ValueError, TypeError, UnicodeDecodeError) as e:
            # En caso de error, usar valor por defecto
            username = "error_decoding"
            print(f"Error decodificando usernameSlug: {e}")

        context = {
            'username': username,
            'usernameSlug': usernameSlug
        }

        return render(request, self.template_name, context)
```

Con esto confirmamos que ya no se usa pickle y cuando tratamos de hacer el RCE de nuevo vemos que no nos llega la terminal y cuando accedemos al perfil si que nos llega el nombre de usuario por lo que se ha parcheado

# APP3
## SQL injection y XSS
El sql injection se encontraba en el login, el cual se encuentra en `/var/www/html/app3/app/views.py`
cambiamos la funcion por
```
@app.route('/login/', methods = ['GET', 'POST'])
def login():
    if g.user is not None and g.user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        # cambiado a ORM de SQLAlchemy para prevenir SQL Injection
        user = User.query.filter_by(user=form.user.data, password=form.password.data).first()
        
        if not user:
            flash('Inicio de sesion incorrecto')
        else:
            login_user(user)
            # cambiado render_template en lugar de render_template_string para prevenir XSS
            return render_template('index.html', name=user.name)
    
    return render_template('login.html', 
        title = 'Sign In',
        form = form)    
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
| **SQL Injection en App2**                          |                                                                             |
| **SSTI en App3**                                   | Sanitizar entradas, evitar `render_template_string()` con datos de usuario. |
| **Buffer Overflow en App5**                        | Usar funciones seguras (`fgets` en lugar de `scanf`), validar longitud.     |
| **Permisos sudo mal configurados**                 | Restringir `sudo` al mínimo necesario, usar `visudo` para editar.           |
| **Secret keys en código**                          | Mover a variables de entorno, usar `.env` o secret managers.                |
| **Tráfico sin cifrar (HTTP)**                      | Implementar HTTPS con certificados autofirmados o Let's Encrypt.            |
| **Directory listing en /static/**                  | Deshabilitar en configuración de Apache/Nginx.                              |
| **FTP anónimo**                                    | Deshabilitar acceso anónimo, usar SFTP/SSH.                                 |
| **Cronjobs inseguros**                             | Revisar que no expongan datos sensibles, limitar permisos.                  |

