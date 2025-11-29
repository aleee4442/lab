#!/usr/bin/env python3
import requests
import re

def deep_debug_login():
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("🔍 DEBUG PROFUNDO - Analizando respuestas del servidor\n")
    
    session = requests.Session()
    
    # 1. Primero obtener la página normalmente
    print("1. Obteniendo página de login...")
    get_response = session.get(login_url)
    print(f"   GET Status: {get_response.status_code}")
    print(f"   GET Cookies: {session.cookies.get_dict()}")
    
    # Extraer CSRF
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
    csrf_token = csrf_match.group(1) if csrf_match else "NO_ENCONTRADO"
    print(f"   CSRF Token: {csrf_token}")
    
    # 2. Probar con contraseña vacía
    print("\n2. Probando con contraseña VACÍA...")
    data_empty = {
        'username': 'admin',
        'password': '',
        'csrfmiddlewaretoken': csrf_token,
        'next': ''
    }
    response_empty = session.post(login_url, data=data_empty, allow_redirects=False)
    print(f"   Status: {response_empty.status_code}")
    print(f"   Headers: {dict(response_empty.headers)}")
    print(f"   Cookies después: {session.cookies.get_dict()}")
    
    # 3. Probar con contraseña incorrecta
    print("\n3. Probando con contraseña INCORRECTA...")
    session2 = requests.Session()  # Nueva sesión
    get_response2 = session2.get(login_url)
    csrf_match2 = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response2.text)
    csrf_token2 = csrf_match2.group(1) if csrf_match2 else "NO_ENCONTRADO"
    
    data_wrong = {
        'username': 'admin',
        'password': 'ESTACONTRASEÑAESINCORRECTA12345',
        'csrfmiddlewaretoken': csrf_token2,
        'next': ''
    }
    response_wrong = session2.post(login_url, data=data_wrong, allow_redirects=False)
    print(f"   Status: {response_wrong.status_code}")
    print(f"   Headers: {dict(response_wrong.headers)}")
    print(f"   Cookies después: {session2.cookies.get_dict()}")
    
    # 4. Probar con usuario que no existe
    print("\n4. Probando con usuario INEXISTENTE...")
    session3 = requests.Session()  # Nueva sesión
    get_response3 = session3.get(login_url)
    csrf_match3 = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response3.text)
    csrf_token3 = csrf_match3.group(1) if csrf_match3 else "NO_ENCONTRADO"
    
    data_fake_user = {
        'username': 'USUARIOQUENOEXISTE12345',
        'password': 'cualquierpassword',
        'csrfmiddlewaretoken': csrf_token3,
        'next': ''
    }
    response_fake = session3.post(login_url, data=data_fake_user, allow_redirects=False)
    print(f"   Status: {response_fake.status_code}")
    print(f"   Headers: {dict(response_fake.headers)}")
    print(f"   Cookies después: {session3.cookies.get_dict()}")
    
    # 5. Analizar diferencias en las respuestas
    print("\n5. Analizando contenido de respuestas...")
    
    print(f"   Respuesta vacía length: {len(response_empty.text)}")
    print(f"   Respuesta incorrecta length: {len(response_wrong.text)}")
    print(f"   Respuesta usuario fake length: {len(response_fake.text)}")
    
    # Buscar mensajes de error específicos
    error_patterns = [
        'invalid', 'incorrect', 'error', 'failed', 'success', 
        'logged in', 'bienvenido', 'welcome'
    ]
    
    for pattern in error_patterns:
        if pattern in response_empty.text.lower():
            print(f"   '{pattern}' en respuesta vacía: SÍ")
        if pattern in response_wrong.text.lower():
            print(f"   '{pattern}' en respuesta incorrecta: SÍ")
        if pattern in response_fake.text.lower():
            print(f"   '{pattern}' en respuesta usuario fake: SÍ")

def test_specific_scenarios():
    """Probar escenarios específicos"""
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("\n🎯 PROBANDO ESCENARIOS ESPECÍFICOS\n")
    
    scenarios = [
        {"username": "admin", "password": "admin", "desc": "Admin con admin"},
        {"username": "admin", "password": "password", "desc": "Admin con password"},
        {"username": "admin", "password": "123456", "desc": "Admin con 123456"},
        {"username": "test", "password": "test", "desc": "Test con test"},
        {"username": "root", "password": "root", "desc": "Root con root"},
    ]
    
    for scenario in scenarios:
        session = requests.Session()
        
        try:
            # Obtener CSRF
            get_response = session.get(login_url)
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
            if not csrf_match:
                print(f"❌ {scenario['desc']}: No CSRF")
                continue
            
            csrf_token = csrf_match.group(1)
            
            # Login
            data = {
                'username': scenario['username'],
                'password': scenario['password'],
                'csrfmiddlewaretoken': csrf_token,
                'next': ''
            }
            
            # Probar con y sin redirección
            response_no_redirect = session.post(login_url, data=data, allow_redirects=False)
            response_with_redirect = session.post(login_url, data=data, allow_redirects=True)
            
            print(f"🔍 {scenario['desc']}:")
            print(f"   Sin redirección: {response_no_redirect.status_code}")
            print(f"   Con redirección: {response_with_redirect.status_code}")
            print(f"   URL final: {response_with_redirect.url}")
            
            # Verificar si estamos en una página diferente al login
            if 'login' not in response_with_redirect.url:
                print(f"   ✅ POSIBLE ÉXITO - No está en página de login")
            else:
                print(f"   ❌ Sigue en login")
                
        except Exception as e:
            print(f"❌ {scenario['desc']}: Error - {e}")

if __name__ == "__main__":
    print("=" * 70)
    print("DEBUG COMPLETO - ENTENDIENDO EL COMPORTAMIENTO DEL LOGIN")
    print("=" * 70)
    
    deep_debug_login()
    test_specific_scenarios()
    
    print("\n" + "=" * 70)
    print("CONCLUSIÓN:")
    print("Si TODAS las contraseñas dan Status 500, hay varias posibilidades:")
    print("1. El servidor tiene un error interno constante")
    print("2. Hay un problema con la aplicación Django")
    print("3. Necesitamos un criterio de detección diferente")
    print("4. La autenticación funciona de forma diferente")
    print("=" * 70)