# BANDIT

[<img src="https://es.web.img2.acsta.net/medias/nmedia/18/35/83/30/18458300.jpg" alt="Imagen" width="400">
](https://overthewire.org/wargames/bandit/)

===========================================
Bandit Wargame – Nivel 0

Host: bandit.labs.overthewire.org
Puerto SSH: 2220
Usuario: bandit0
Contraseña: bandit0

Paso 1 – Conexión SSH:
Conéctate al servidor usando SSH. Verifica siempre usuario, host y puerto antes de conectar.
Comando:
"ssh bandit0@bandit.labs.overthewire.org
 -p 2220"

Paso 2 – Confirmar directorio actual:
Verifica en qué directorio estás para conocer tu posición en el sistema.
Comando:
"pwd"

Paso 3 – Listar archivos:
Lista los archivos y directorios presentes para localizar tu objetivo.
Comando:
"ls -l"

Paso 4 – Leer la flag:
Extrae la flag del archivo readme. Esta será la contraseña para el Nivel 1.
Comando:
"cat readme"

Reflexión:

Reconocimiento: pwd → ubicación actual

Enumeración: ls -l → archivos/directorios presentes

Explotación/Extracción: cat readme → obtener la flag

Flag Nivel 0 (Base64, solo para seguimiento interno):
"WmpMak5tTDpGdnZ5Um5yYjJyZk5XT1pPVGE2aXA1SWY="

===========================================
Bandit Wargame – Nivel 1

Host: bandit.labs.overthewire.org
Puerto SSH: 2220
Usuario: bandit1
Contraseña: (obtenida del Nivel 0)

Paso 1 – Conexión SSH:
"ssh bandit1@bandit.labs.overthewire.org
 -p 2220"

Paso 2 – Confirmar directorio actual:
"pwd"

Paso 3 – Listar archivos:
"ls -l"

Paso 4 – Leer la flag:
El archivo comienza con -, usa ./ para evitar confusión con opciones de comando:
"cat ./-"

Reflexión:

Reconocimiento: pwd → ubicación actual

Enumeración: ls -l → archivos/directorios

Explotación/Extracción: cat ./- → obtener la flag

Flag Nivel 1 (Base64, solo para seguimiento interno):
"MjYzSkdKUGZnVTZMdGRFdmdmV1UxWFA1eWFjMjltRng="

===========================================
Bandit Wargame – Nivel 2

Host: bandit.labs.overthewire.org
Puerto SSH: 2220
Usuario: bandit2
Contraseña: (obtenida del Nivel 1)

Paso 1 – Conexión SSH:
"ssh bandit2@bandit.labs.overthewire.org
 -p 2220"

Paso 2 – Confirmar directorio actual:
"pwd"

Paso 3 – Listar archivos y permisos:
"ls -l"

Paso 4 – Leer la flag:
El archivo tiene espacios y guiones, usa ./ y comillas para acceder correctamente:
"cat './--spaces in this filename--'"

Reflexión:

Reconocimiento: pwd → ubicación actual

Enumeración: ls -l → archivos y permisos

Explotación/Extracción: cat './--spaces in this filename--' → obtener la flag

Flag Nivel 2 (Base64, solo para seguimiento interno):
"TU5rOEtOSDNVc2lpbzQ1UFJVRW9ERlBxZnhMUGxTbXg="

===========================================
Bandit Wargame – Nivel 3

Host: bandit.labs.overthewire.org
Puerto SSH: 2220
Usuario: bandit3
Contraseña: (obtenida del Nivel 2)

Paso 1 – Conexión SSH:
"ssh bandit3@bandit.labs.overthewire.org
 -p 2220"

Paso 2 – Confirmar directorio actual:
"pwd"

Paso 3 – Listar archivos y subdirectorios:
"ls -l"
"ls -lR ./inhere"

Paso 4 – Localizar la flag sin asumir tamaño:
"find ./inhere -type f"

Paso 5 – Leer la flag:
"cat './inhere/...Hiding-From-You'"

Reflexión:

Reconocimiento: pwd → ubicación actual

Enumeración: ls -l / ls -lR → archivos/subdirectorios

Localización estratégica: find ./inhere -type f → identificar el archivo

Explotación/Extracción: cat './inhere/...Hiding-From-You' → obtener la flag

Flag Nivel 3 (Base64):
"MldtckRGUm1KSXEzSVB4bmVBYU1HaGFwMHBGaEZuSk4="

===========================================

