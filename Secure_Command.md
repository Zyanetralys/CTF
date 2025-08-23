# SECURE COMMAND

## 1. RECONOCIMIENTO

Acción: Escaneo de puertos de la máquina objetivo
Comando:
"nmap -sV 172.20.4.179"

Resultado:

Puerto abierto: 22

Servicio: ssh

## 2. ACCESO SSH

Acción: Conexión al objetivo con usuario inicial
Comando:
"ssh hackviser@172.20.4.179"
Contraseña: "hackviser"

Resultado: Acceso concedido

Mensaje de bienvenida: "Try hackviser ^_^"

## 3. ESCALACIÓN DE PRIVILEGIOS

Acción: Intento de cambio a usuario root
Comando:
"su root"
Contraseña tentativa: "root"

Resultado: Fallo de autenticación

No se puede escalar a root con credenciales conocidas

Acción secundaria: Obtener shell interactiva para mejorar manejo de comandos
Comando:
"python3 -c 'import pty; pty.spawn("/bin/bash")'"

Resultado: Shell semi-interactiva obtenida

## 4. EXPLORACIÓN DEL DIRECTORIO

Acción: Listado de archivos del usuario
Comandos:
"ls -lha"
"ls -A"

Resultado:

Archivos visibles: ".bashrc"

Archivos secretos no encontrados

## 5. INSPECCIÓN DE ARCHIVOS DE CONFIGURACIÓN

Acción: Lectura del archivo ".bashrc"
Comando:
"cat ~/.bashrc"

Resultado:

Contenido estándar de bash

Historial de comandos eliminado: "rm -rf ~/.bash_history"

No contiene información secreta

## 6. RESPUESTA FINAL DE LA MISIÓN

Pregunta: What is the master's advice?
Formato requerido: **** *******
Respuesta: "read carefully"

Acción: Registrar la respuesta en la plataforma o archivo de entrega
Comando ejemplo:
"echo 'read carefully' > answer.txt"

## 7. OBSERVACIONES

La escalación a root no era necesaria para completar la misión.

La información clave se encontraba en la instrucción del sistema y la observación del mensaje del master.

Shell interactiva permitió ejecutar comandos básicos a pesar de las restricciones.

Comprobar siempre las instrucciones de la misión antes de realizar intentos de fuerza bruta o exploración innecesaria.
