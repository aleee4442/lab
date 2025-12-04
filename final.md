# Informe de Práctica 1: Análisis de Vulnerabilidades en Entorno Web

---

**Universidad UNIE**  
**Seguridad Informática y Ciberseguridad en la Empresa**  
**Curso 2025/2026**

---

## Integrantes del Grupo

- **Alejandro Gonzalo Millón**
- **Daniel Relloso Orcajo**
- **Daniel Willson Pastor**

**Fecha de entrega:** 4 de diciembre de 2025

---

## Introducción

Nuestra misión ha sido emular las tácticas de un atacante real, aplicando metodologías estructuradas de pentesting para descubrir y explotar vulnerabilidades en tres aplicaciones web independientes (App1, App2 y App3). Cada aplicación, desarrollada con diferentes tecnologías y arquitecturas, presentaba su propio conjunto de debilidades, algunas evidentes y otras ocultas tras capas de código aparentemente seguro.

Hemos seguido una metodología en fases, comenzando con el reconocimiento pasivo y activo del objetivo, identificando servicios expuestos, puertos abiertos y tecnologías subyacentes. Posteriormente, hemos realizado una enumeración exhaustiva de cada aplicación, buscando vectores de ataque como:

- **Exposición de información sensible:** Código fuente, credenciales, esquemas de base de datos...
- **Vulnerabilidades de inyección:** SQL, SSTI, RCE, comandos...
- **Fallos de autenticación y autorización:** Accesos no controlados, bypass de login...
- **Errores de configuración:** Debug activado, backups accesibles públicamente...

Para cada vulnerabilidad identificada, hemos documentado no solo su explotación técnica, sino también el impacto potencial en un entorno real. De las mitigaciones nos centraremos en la siguiente práctica.

---

## Fase 1: Reconocimiento y Enumeración


**Comando Ejecutado:**

```bash
nmap 192.168.88.128
```

**Resultados Obtenidos:**

![Nmap a UBUNTU](photos/NMAP.png)

### Análisis Detallado por Puerto

#### Puerto 21/tcp - FTP (vsftpd)

```text
21/tcp    open   ftp     vsftpd (broken: both local and anonymous access disabled!)
```

**Observaciones:**

- Servidor: vsftpd (Very Secure FTP Daemon)
- Estado: Acceso anónimo deshabilitado según el escaneo
- Conclusión: No podemos acceder sin credenciales válidas. Posible vector si encontramos credenciales en otro lugar.

#### Puerto 22/tcp - SSH

```text
22/tcp    open   ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a1:a0:86:5d:7c:7f:4e:f4:ab:ca:90:0d:49:89:e4:7c (ECDSA)
|_  256 30:c4:82:38:86:3e:08:3e:87:5c:a8:08:f6:8d:fe:e1 (ED25519)
```

**Observaciones:**

- Versión: OpenSSH 9.6p1 (actual, sin vulnerabilidades críticas conocidas)
- Sistema: Ubuntu 3ubuntu13.11
- Conclusión: SSH normalmente es difícil de vulnerar directamente. Requeriría credenciales válidas o una vulnerabilidad específica en esta versión.

#### Puerto 80/tcp - HTTP

```text
80/tcp    open   http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

**Observaciones:**

- Servidor: Apache 2.4.58 en Ubuntu
- Conclusión: Puerto principal para aplicaciones web. Posibles vectores:
  - Aplicaciones vulnerables (App1, App2, App3)
  - Configuraciones incorrectas
  - Vulnerabilidades en Apache

#### Puerto 3306/tcp - MySQL/MariaDB

```text
3306/tcp  open   mysql   MariaDB 10.3.23 or earlier (unauthorized)
```

**Observaciones:**

- Base de datos: MariaDB 10.3.23 o anterior
- Estado: "unauthorized" - acceso denegado sin credenciales
- Conclusión: Potencial para:
  - Inyección SQL si las apps tienen vulnerabilidades
  - Acceso directo si encontramos credenciales
  - Enumeración si la configuración lo permite

#### Puerto 5555/tcp - Freeciv

```text
5555/tcp open  freeciv
```

**Observaciones:**

- Servicio: Freeciv (juego de estrategia)
- Conclusión: Posible vector si:
  - Hay vulnerabilidades en el servicio
  - Se usa para algo diferente a Freeciv (servicio mal etiquetado)

#### Puerto 9001/tcp - HTTP (SimpleHTTPServer)

```text
9001/tcp  open   http    SimpleHTTPServer 0.6 (Python 3.13.0)
|_http-server-header: SimpleHTTP/0.6 Python/3.13.0
|_http-title: Directory listing for /
```

**Observaciones CRÍTICAS:**

- Servidor: SimpleHTTPServer de Python 3.13.0
- **LISTADO DE DIRECTORIOS HABILITADO** - ¡Grave error de configuración!
- Conclusión: Posible exposición de archivos sensibles. Primer vector de ataque importante.

### Resumen de Hallazgos Iniciales

#### Riesgos Identificados:

| Puerto | Servicio | Riesgo | Acción Recomendada |
|--------|----------|--------|-------------------|
| 21 | FTP | Medio | Buscar credenciales en otros vectores |
| 22 | SSH | Bajo | Último recurso, difícil de explotar |
| 80 | HTTP | ALTO | Principal vector - 3 aplicaciones web |
| 3306 | MariaDB | Medio-Alto | Depende de vulnerabilidades en apps |
| 5555 | Freeciv | Bajo | Investigar si es realmente Freeciv |
| 9001 | HTTP | CRÍTICO | Listado directorios - posible filtración |

#### Plan de Ataque Inicial:

1. **Primer objetivo:** Puerto 9001 - Investigar listado de directorios
2. **Segundo objetivo:** Puerto 80 - Enumerar aplicaciones web
3. **Tercer objetivo:** Buscar conexiones entre servicios
4. **Cuarto objetivo:** Credenciales para servicios restringidos

### Conclusiones Tácticas

- El servidor está relativamente bien cerrado - solo puertos esenciales abiertos
- El error de configuración en el puerto 9001 es nuestra puerta de entrada principal
- La presencia de MariaDB sugiere que las aplicaciones usan bases de datos → posible SQL injection
- Tres aplicaciones web distintas en el puerto 80 sugieren arquitectura modular con posibles fallos en cada una

---

## Vulnerabilidades Identificadas

A continuación se presentan las vulnerabilidades descubiertas durante el proceso de análisis y explotación del objetivo:

