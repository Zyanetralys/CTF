# 🏴‍☠️ BANDIT WARGAME

[![Bandit](https://es.web.img2.acsta.net/medias/nmedia/18/35/83/30/18458300.jpg)](https://overthewire.org/wargames/bandit/)

> **Juego de guerra de seguridad informática** - Desarrolla habilidades en terminal Linux y seguridad

## 📋 Información General

- **Host**: `bandit.labs.overthewire.org`
- **Puerto SSH**: `2220`
- **Objetivo**: Encontrar flags para avanzar al siguiente nivel

---

## 🎯 Nivel 0

### Credenciales
- **Usuario**: `bandit0`
- **Contraseña**: `bandit0`

### Pasos

#### 1️⃣ Conexión SSH
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

#### 2️⃣ Reconocimiento del entorno
```bash
pwd    # Confirmar directorio actual
```

#### 3️⃣ Enumeración de archivos
```bash
ls -l  # Listar archivos y permisos
```

#### 4️⃣ Extracción de la flag
```bash
cat readme
```

### 🧠 Metodología
- **Reconocimiento**: `pwd` → ubicación actual
- **Enumeración**: `ls -l` → archivos/directorios presentes
- **Explotación**: `cat readme` → obtener la flag

### 🔐 Flag (Base64)
```
WmpMak5tTDpGdnZ5Um5yYjJyZk5XT1pPVGE2aXA1SWY=
```

---

## 🎯 Nivel 1

### Credenciales
- **Usuario**: `bandit1`
- **Contraseña**: *Obtenida del Nivel 0*

### Pasos

#### 1️⃣ Conexión SSH
```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
```

#### 2️⃣ Reconocimiento del entorno
```bash
pwd    # Confirmar directorio actual
```

#### 3️⃣ Enumeración de archivos
```bash
ls -l  # Listar archivos y permisos
```

#### 4️⃣ Extracción de la flag
```bash
cat ./-
```
> ⚠️ **Nota**: El archivo comienza con `-`, usar `./` evita confusión con opciones de comando

### 🧠 Metodología
- **Reconocimiento**: `pwd` → ubicación actual
- **Enumeración**: `ls -l` → archivos/directorios
- **Explotación**: `cat ./-` → manejo de nombres especiales

### 🔐 Flag (Base64)
```
MjYzSkdKUGZnVTZMdGRFdmdmV1UxWFA1eWFjMjltRng=
```

---

## 🎯 Nivel 2

### Credenciales
- **Usuario**: `bandit2`
- **Contraseña**: *Obtenida del Nivel 1*

### Pasos

#### 1️⃣ Conexión SSH
```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
```

#### 2️⃣ Reconocimiento del entorno
```bash
pwd    # Confirmar directorio actual
```

#### 3️⃣ Enumeración de archivos
```bash
ls -l  # Listar archivos y permisos
```

#### 4️⃣ Extracción de la flag
```bash
cat './spaces in this filename'
# o alternativamente:
cat "spaces in this filename"
```
> ⚠️ **Nota**: Archivos con espacios requieren comillas o escape

### 🧠 Metodología
- **Reconocimiento**: `pwd` → ubicación actual
- **Enumeración**: `ls -l` → archivos y permisos
- **Explotación**: manejo de espacios en nombres de archivo

### 🔐 Flag (Base64)
```
TU5rOEtOSDNVc2lpbzQ1UFJVRW9ERlBxZnhMUGxTbXg=
```

---

## 🎯 Nivel 3

### Credenciales
- **Usuario**: `bandit3`
- **Contraseña**: *Obtenida del Nivel 2*

### Pasos

#### 1️⃣ Conexión SSH
```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
```

#### 2️⃣ Reconocimiento del entorno
```bash
pwd    # Confirmar directorio actual
```

#### 3️⃣ Enumeración completa
```bash
ls -l           # Listar contenido actual
ls -la inhere/  # Incluir archivos ocultos en subdirectorio
# o recursivamente:
ls -lRa ./inhere
```

#### 4️⃣ Localización estratégica
```bash
find ./inhere -type f  # Buscar todos los archivos
```

#### 5️⃣ Extracción de la flag
```bash
cat './inhere/...Hiding-From-You'
```

### 🧠 Metodología
- **Reconocimiento**: `pwd` → ubicación actual
- **Enumeración**: `ls -la` → incluir archivos ocultos
- **Localización**: `find` → identificación sistemática
- **Explotación**: acceso a archivos ocultos con nombres especiales

### 🔐 Flag (Base64)
```
MldtckRGUm1KSXEzSVB4bmVBYU1HaGFwMHBGaEZuSk4=
```

---

## 📚 Conceptos Clave Aprendidos

### Nivel 0
- Conexión SSH básica
- Navegación básica en terminal
- Lectura de archivos con `cat`

### Nivel 1
- Manejo de archivos con nombres especiales (`-`)
- Uso de rutas relativas (`./`)

### Nivel 2
- Archivos con espacios en el nombre
- Escape de caracteres especiales

### Nivel 3
- Archivos ocultos (que comienzan con `.`)
- Búsqueda recursiva de archivos
- Comando `find` para localización

## 🛠️ Comandos Útiles

```bash
# Navegación y reconocimiento
pwd                    # Directorio actual
ls -la                # Listar todo (incluye ocultos)
ls -lR                # Listar recursivamente

# Búsqueda de archivos
find . -name "*.txt"  # Buscar por nombre
find . -type f        # Buscar solo archivos
find . -type d        # Buscar solo directorios

# Lectura de archivos
cat filename          # Leer archivo completo
head filename         # Primeras 10 líneas
tail filename         # Últimas 10 líneas

# Manejo de nombres especiales
cat ./filename        # Archivo que empieza con -
cat "file name"       # Archivo con espacios
cat 'file name'       # Alternativa con comillas simples
```

## 🔗 Utilidades

- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/)
- [Manual de Linux](https://man7.org/linux/man-pages/)
- [SSH Tutorial](https://www.ssh.com/academy/ssh)

---

Nivel 4

Usuario: bandit4
Contraseña: Nivel 3

Paso 1 – Conexión SSH:
"ssh bandit4@bandit.labs.overthewire.org
 -p 2220"

Paso 2 – Confirmar directorio actual:
"pwd"

Paso 3 – Explorar directorio inhere y archivos especiales:
"ls -la ./inhere"
"ls -lR ./inhere"
"find ./inhere -type f"

Paso 4 – Identificar la flag usando contenido legible:

for f in ./inhere/-file*; do echo "$f:"; strings "$f"; done


Observa qué archivo contiene contenido legible de la flag.

Paso 5 – Leer la flag:
"cat './inhere/-file07'"

Flag Nivel 4 (Base64):
"NG9RWVZQa3hab09FRU9PNXBUVzgxRkI4ajhseFhHVVF3"

Reflexión:

Reconocimiento: pwd → ubicación actual

Enumeración: ls -la / ls -lR → inspección completa

Localización: find → identificar todos los archivos regulares

Explotación/Extracción: strings / cat → encontrar contenido legible y extraer la flag
