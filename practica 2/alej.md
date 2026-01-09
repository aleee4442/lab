# Todas las APPS
## Cambio de contraseña
Para hacer el cambio de contraseña lo vamos a hacer usando el propio django. Para cada app tenemos que ir a donde se encuentra el codigo de cada app `cd /var/www/html/app1` y ejecutamos el venv con 
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

## Panel de administración no accesible
Para securizar más el panel de administración hemos decidido bloquear el acceso por ip, para esto tenemos que modificar un archivo de apache encontrado en `/etc/apache2/sites-available/app1.conf` donde tenemos que añadir lo siguiente:
```
<Location /admin>
	<RequireAny>
		Require ip 127.0.0.1
		Require ip 192.168.17.0/24
	 </RequireAny>
</Location>
```
Con esto permitimos que se pueda acceder de forma local y con las ips que nosotros asignemos, si intentas entrar con otra ip te sale lo siguiente
![[Pasted image 20260108114434.png]]
## Debug en el login
Antes cuando intentabas iniciar sesión desde app1.unie/users/login independientemente de que estuviese bien o mal te saltaba un debug con información. Para cambiar esto nos tenemos que ir al archivo encontrado en `/var/www/html/app1/app1/settings/local.py`

```
DEBUG = env.bool('DJANGO_DEBUG', default=False)
TEMPLATES[0]['OPTIONS']['debug'] = DEBUG
```

Cambiado default=True por =False, ahora en vez de hacer el debug te sale lo siguiente
![[Pasted image 20260108120744.png]]
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
```python
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

## APP4 (9001)
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

# Maria DB
La base de datos estaba configurada para escuchar en todas las interfaces como se puede observar
![[Pasted image 20260108115221.png]]
Para modificar esto simplemente tenemos que modificar el siguiente archivo `/etc/mysql/mariadb.conf.d/50-server.cnf` y cambiar el bind address 0.0.0.0 por
```
bind-address = 127.0.0.1
```
Tras recargar apache vemos que efectivamente ahora se ha cambiado y solo escucha de forma local
![[Pasted image 20260108115526.png]]


# Firewall
Vamos a utilizar el firewall con el comando ufw
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
```
Primero indicamos las normas normales donde bloqueamos todo el trafico que entre y aceptamos todo el que salga de nuestra maquina, ahora configuraremos puerto por puerto
```
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 21/tcp      # FTP
sudo ufw allow 5555/tcp    # app5
```
Estos son los puertos que se necesitan por lo que los ponemos en allow y ahora vamos a hacer que al puerto 9001 solo se pueda acceder de forma local (lo ponemos tambien con ufw pese a cambiar la configuracion por si acaso)
```
sudo ufw allow from 127.0.0.1 to any port 9001
sudo ufw deny 9001
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

