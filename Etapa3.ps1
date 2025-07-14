# ===============================
#  ETAPA 3: OPTIMIZACION DE PROCESOS Y SERVICIOS
#  Detiene procesos innecesarios y servicios que consumen recursos
# ===============================

param(
    [switch]$DebugMode,
    [ValidateSet('auto','estandar')][string]$AffinityMode = 'auto'
)

# ===============================
#  VERIFICACION DE PERMISOS
# ===============================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Esta etapa requiere permisos de administrador" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Yellow
Write-Host "   ETAPA 3: OPTIMIZACION DE PROCESOS/SERVICIOS" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

# Variables globales para backup
$script:stoppedServices = @()

# ===============================
#  FUNCIONES DE OPTIMIZACION DE PROCESOS
# ===============================
function Stop-ProcessesForGaming {
    Write-Host "[PROC] Deteniendo procesos innecesarios para gaming..." -ForegroundColor Green
    
    # Lista de procesos no criticos que pueden impactar el rendimiento
    $processesToStop = @(
        'TeamViewer',
        'TeamViewer_Service',
        'OneDrive',
        'SkypeApp',
        'SkypeHost',
        'Spotify',
        'uTorrent',
        'BitTorrent',
        'Notepad++',
        'winword',
        'excel',
        'powerpnt',
        'outlook',
        'thunderbird',
        'obs64',
        'obs32',
        'XSplit',
        'Streamlabs',
        'Photoshop',
        'Premiere',
        'After Effects',
        'Illustrator',
        'Lightroom',
        'Blender',
        'Maya',
        '3dsMax',
        'devenv',
        'unity',
        'UnrealEngine',
        'Slack',
        'Teams',
        'Zoom',
        'WhatsApp',
        'Telegram',
        'VLC',
        'MPC-HC',
        'PotPlayer',
        'Kodi',
        'Plex',
        'iTunes',
        'MusicBee',
        'foobar2000',
        'CCleaner',
        'Malwarebytes',
        'GameBar',
        'GameBarPresenceWriter',
        'WinStore.App',
        'YourPhone',
        'CompatTelRunner',
        'SearchUI'
    )
    
    $stoppedCount = 0
    foreach ($processName in $processesToStop) {
        try {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    try {
                        $process.Kill()
                        $stoppedCount++
                        Write-Host "[PROC] Detenido: $processName (PID: $($process.Id))" -ForegroundColor Gray
                    } catch {
                        # Ignorar errores si el proceso ya no existe o no se puede detener
                    }
                }
            }
        } catch {
            # Ignorar errores al buscar procesos
        }
    }
    
    Write-Host "[PROC] Procesos detenidos: $stoppedCount" -ForegroundColor Green
}

function Stop-ServicesForGaming {
    Write-Host "[SERV] Deteniendo servicios innecesarios para gaming..." -ForegroundColor Green
    
    # Lista de servicios no criticos que pueden impactar el rendimiento
    $servicesToStop = @(
        'Windows Search',
        'Superfetch',
        'SysMain',
        'Themes',
        'Windows Update',
        'wuauserv',
        'BITS',
        'Spooler',
        'Fax',
        'TabletInputService',
        'WSearch',
        'WerSvc',
        'DiagTrack',
        'dmwappushservice',
        'lfsvc',
        'MapsBroker',
        'NetTcpPortSharing',
        'RemoteAccess',
        'RemoteRegistry',
        'SessionEnv',
        'TermService',
        'Themes',
        'UxSms',
        'WbioSrvc',
        'WcsPlugInService',
        'WdiServiceHost',
        'WdiSystemHost',
        'WebClient',
        'Wecsvc',
        'wercplsupport',
        'WerSvc',
        'WinHttpAutoProxySvc',
        'Winmgmt',
        'WinRM',
        'WwanSvc',
        'XblAuthManager',
        'XblGameSave',
        'XboxNetApiSvc',
        'XboxGipSvc',
        'defragsvc',
        'HomeGroupListener',
        'HomeGroupProvider',
        'iphlpsvc',
        'LanmanServer',
        'MSDTC',
        'MSiSCSI',
        'msiserver',
        'PolicyAgent',
        'SCardSvr',
        'SCPolicySvc',
        'SNMPTRAP',
        'swprv',
        'VSS',
        'W32Time',
        'WalletService',
        'WbioSrvc',
        'WcsPlugInService',
        'WdiServiceHost',
        'WdiSystemHost',
        'WebClient',
        'Wecsvc',
        'wercplsupport',
        'WerSvc',
        'WinHttpAutoProxySvc',
        'Winmgmt',
        'WinRM',
        'WwanSvc'
    )
    
    $stoppedCount = 0
    foreach ($serviceName in $servicesToStop) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                try {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    $script:stoppedServices += $serviceName
                    $stoppedCount++
                    Write-Host "[SERV] Detenido: $serviceName" -ForegroundColor Gray
                } catch {
                    # Ignorar errores si el servicio no se puede detener
                }
            }
        } catch {
            # Ignorar errores al buscar servicios
        }
    }
    
    Write-Host "[SERV] Servicios detenidos: $stoppedCount" -ForegroundColor Green
}

function Restore-ServicesForGaming {
    Write-Host "[SERV] Restaurando servicios detenidos..." -ForegroundColor Green
    
    $restoredCount = 0
    foreach ($serviceName in $script:stoppedServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Stopped') {
                try {
                    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $restoredCount++
                    Write-Host "[SERV] Restaurado: $serviceName" -ForegroundColor Gray
                } catch {
                    # Ignorar errores si el servicio no se puede iniciar
                }
            }
        } catch {
            # Ignorar errores al buscar servicios
        }
    }
    
    Write-Host "[SERV] Servicios restaurados: $restoredCount" -ForegroundColor Green
    $script:stoppedServices = @()
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE3] Iniciando optimizacion de procesos y servicios..." -ForegroundColor Green

# Detener procesos innecesarios
Stop-ProcessesForGaming

# Detener servicios innecesarios
Stop-ServicesForGaming

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 3: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE3] Optimizacion de procesos y servicios completada" -ForegroundColor Green

# Guardar informacion para restauracion posterior
$serviceInfo = @{
    StoppedServices = $script:stoppedServices
    Timestamp = Get-Date
}

# Crear archivo de configuracion temporal
$configPath = Join-Path $env:TEMP "OptimizadorServicios.json"
$serviceInfo | ConvertTo-Json | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "[INFO] Configuracion guardada en: $configPath" -ForegroundColor Gray
