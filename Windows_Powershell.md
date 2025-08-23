CTF Windows Powershell

Alias “HoldenManeuver”
Comando: "Get-Alias HoldenManeuver"
Respuesta: Get-Runspace

Cantidad de libros en Documents\Books
Comando: "Get-ChildItem C:\Users\Administrator\Documents\Books | Measure-Object"
Respuesta: 9

Cmdlet para mostrar procesos activos en el sistema
Comando: "Get-Process"
Respuesta: Get-Process

Cantidad de servicios con “MCRN” en su nombre
Comando: "Get-Service | Where-Object {$_.Name -like 'MCRN'} | Measure-Object"
Respuesta: 5

Cantidad de usuarios activos en Active Directory
Comando: "Get-ADUser -Filter * | Where-Object {$_.Enabled -eq $true} | Measure-Object"
Respuesta: 10

Grupo local con descripción que mencione certificados
Comando: "Get-LocalGroup | Where-Object {$_.Description -like 'certificate'}"
Respuesta: Cert Publishers

Comando para descargar archivos desde internet o red
Respuesta: Invoke-WebRequest

Número de build del sistema
Comando: "systeminfo | findstr /B /C:'OS Build'"
Respuesta: [Indicar el número de build según el sistema]

HotFixID de la actualización instalada
Comando: "Get-HotFix"
Respuesta: KB4464455

Windows Defender activo en el servidor
Comando: "Get-Service WinDefend"
Respuesta: No

Usuario con permisos de solo lectura en 'Abaddon's Gate'
Comando: "Get-Acl 'C:\Users\Administrator\Documents\Books\Abaddon's Gate' | Format-List"
Respuesta: No
