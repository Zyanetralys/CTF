# CTF Windows PowerShell

## Información de Conexión
- **Protocolo de Acceso:** SSH
- **Usuario:** Administrator  
- **Credencial:** password123!
- **IP Objetivo:** 172.20.19.36

## Procedimientos de Reconocimiento

### 1. Identificación de Alias de Comando
**Objetivo:** Determinar comando asociado al alias 'HoldenManeuver'
```powershell
Get-Alias HoldenManeuver
```
**Resultado:** Get-Runspace

### 2. Enumeración de Archivos de Inteligencia
**Objetivo:** Contabilizar libros en Documents\Books
```powershell
Get-ChildItem C:\Users\Administrator\Documents\Books | Measure-Object
```
**Resultado:** 9 elementos

### 3. Análisis de Procesos Activos
**Objetivo:** Identificar cmdlet para listado de procesos
```powershell
Get-Process
```
**Resultado:** Get-Process

### 4. Búsqueda de Servicios de Interés
**Objetivo:** Localizar servicios con designación 'MCRN'
```powershell
Get-Service | Where-Object {$_.Name -like "*MCRN*"} | Measure-Object
```
**Resultado:** 5 servicios

### 5. Auditoría de Personal Activo
**Objetivo:** Enumerar usuarios habilitados en Active Directory
```powershell
Get-ADUser -Filter * | Where-Object {$_.Enabled -eq $true} | Measure-Object
```
**Resultado:** 10 usuarios activos

### 6. Identificación de Grupos de Certificación
**Objetivo:** Localizar grupo local relacionado con certificados
```powershell
Get-LocalGroup | Where-Object {$_.Description -like "*certificate*"}
```
**Resultado:** Cert Publishers

### 7. Capacidades de Descarga de Datos
**Objetivo:** Comando para transferencia de archivos vía red
**Resultado:** Invoke-WebRequest

### 8. Información del Sistema
**Objetivo:** Obtener número de build del sistema
```powershell
systeminfo | findstr /B /C:"OS Build"
```
**Nota:** Verificar salida específica del sistema objetivo

### 9. Historial de Actualizaciones
**Objetivo:** Identificar HotFixID instalado
```powershell
Get-HotFix
```
**Resultado:** KB4464455

### 10. Estado de Defensa del Sistema
**Objetivo:** Verificar si Windows Defender está operativo
```powershell
Get-Service WinDefend
```
**Resultado:** No (Servicio no encontrado)

### 11. Análisis de Permisos de Archivos
**Objetivo:** Usuario con acceso de solo lectura a 'Abaddon's Gate'

**Comando Principal:**
```powershell
Get-Acl "C:\Users\Administrator\Documents\Books\Abaddon's Gate.txt" | Format-List
```

**Comando Alternativo para Verificación:**
```powershell
icacls "C:\Users\Administrator\Documents\Books\Abaddon's Gate.txt"
```

**Comando de Enumeración Completa:**
```powershell
Get-ChildItem "C:\Users\Administrator\Documents\Books\" | ForEach-Object {
    Write-Host "--- $($_.Name) ---";
    Get-Acl $_.FullName | Select-Object -ExpandProperty Access | Select-Object IdentityReference, FileSystemRights
}
```

**Resultado:** c.avasarala (ReadAndExecute, Synchronize)

## Comandos de Utilidad Adicional

### Verificación de Conectividad
```powershell
Test-NetConnection -ComputerName [target] -Port [port]
```

### Enumeración de Usuarios Locales
```powershell
Get-LocalUser
net localgroup "Users"
```

### Búsqueda de Archivos Específicos
```powershell
Get-ChildItem -Path "C:\" -Recurse -Name "*[filename]*" 2>$null
```

### Análisis Detallado de Permisos
```powershell
Get-Acl [filepath] | Select-Object -ExpandProperty Access | Format-List *
```

## Notas
- Utilizar comillas dobles para rutas con espacios o caracteres especiales
- El comando `icacls` proporciona salida más compacta para permisos
- Verificar tanto archivos con extensión como sin extensión cuando sea relevante
- Los permisos `ReadAndExecute, Synchronize` equivalen a acceso de solo lectura para archivos
