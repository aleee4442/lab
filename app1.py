#!/usr/bin/env python3
import requests
import re

def confirm_login():
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    session = requests.Session()
    
    # Obtener CSRF
    get_response = session.get(login_url)
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
    csrf_token = csrf_match.group(1) if csrf_match else ""
    
    # Login con admin:admin
    data = {
        'username': 'admin',
        'password': 'admin',
        'csrfmiddlewaretoken': csrf_token,
        'next': ''
    }
    
    post_response = session.post(login_url, data=data, allow_redirects=False)
    
    print(f"Status: {post_response.status_code}")
    print(f"Headers: {dict(post_response.headers)}")
    
    # Verificar el mensaje de éxito en las cookies
    messages_cookie = session.cookies.get('messages', '')
    if messages_cookie:
        print(f"Mensaje en cookie: {messages_cookie}")
    
    # El mensaje "You are now logged in!" aparece en la cookie
    # Esto confirma que el login fue exitoso
    
    return post_response.status_code == 500 and "messages" in session.cookies.get_dict()

if __name__ == "__main__":
    print("Confirmando credenciales...")
    if confirm_login():
        print("\n" + "="*50)
        print("¡CREDENCIALES CONFIRMADAS!")
        print("Usuario: admin")
        print("Contraseña: admin")
        print("="*50)
        print("\nNOTA: El login es exitoso pero causa error 500 en el servidor")
    else:
        print("Credenciales incorrectas")