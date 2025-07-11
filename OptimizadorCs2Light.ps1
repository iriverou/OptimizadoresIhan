# ===============================
#  OPTIMIZADOR DE PROPOSITO GENERAL PARA JUEGO CS2 version Light
#  Archivo base para automatizacion y optimizacion avanzada de Counter-Strike 2
#  (Desarrollo modular por etapas)
# ===============================

param(
    [switch]$DebugMode,
    [ValidateSet('auto','estandar')][string]$AffinityMode = 'auto'
)

# ===============================
#  VERIFICACION DE VERSION DE POWERSHELL
# ===============================
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "[ERROR] Este script requiere PowerShell 5.1 o superior."
    Write-Host "Version detectada: $($PSVersionTable.PSVersion)"
    exit 1
}

# ===============================
#  AUTO-ELEVACION A ADMINISTRADOR
# ===============================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ADMIN] Reiniciando como administrador..." -ForegroundColor Yellow
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($DebugMode) { $argList += " -DebugMode" }
    if ($AffinityMode -ne 'auto') { $argList += " -AffinityMode $AffinityMode" }
    Start-Process -FilePath "powershell" -ArgumentList $argList -Verb RunAs
    exit
}

# ===============================
#  VERIFICACION DE INSTANCIA UNICA
# ===============================
$scriptName = [System.IO.Path]::GetFileName($MyInvocation.MyCommand.Path)
$running = Get-Process | Where-Object { $_.ProcessName -like "$($scriptName -replace '.ps1$','')*" -and $_.Id -ne $PID }
if ($running) {
    Write-Host "[WARN] Ya hay una instancia ejecutandose" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   OPTIMIZADOR CS2 LIGHT - INICIANDO" -ForegroundColor White
Write-Host "   Modo Affinity: $AffinityMode | Debug: $($DebugMode.ToString())" -ForegroundColor Gray
Write-Host "==============================================" -ForegroundColor Cyan

# Variables globales para cache
$script:CoreInfoCache = $null
$script:CoreInfoCacheValid = $false

# ===============================
#  FUNCIONES DE UTILIDADES SYSINTERNALS
# ===============================
function Get-RAMMapPath {
    # Obtener la ruta del script de forma robusta
    $scriptRoot = if ($PSScriptRoot) { 
        [string]$PSScriptRoot 
    } elseif ($MyInvocation.MyCommand.Path) { 
        Split-Path -Parent $MyInvocation.MyCommand.Path 
    } else { 
        Get-Location 
    }
    
    # Asegurar que sea una string y no un array
    $root = [string]$scriptRoot
    
    # Lista de posibles nombres de RAMMap (orden de preferencia)
    $candidates = @(
        (Join-Path -Path $root -ChildPath 'RAMMap64.exe'),
        (Join-Path -Path $root -ChildPath 'RAMMap64a.exe'),
        (Join-Path -Path $root -ChildPath 'RAMMap.exe')
    )
    
    foreach ($candidate in $candidates) { 
        if (Test-Path -Path $candidate) { 
            return $candidate 
        } 
    }
    return $null
}

function Get-CoreInfoPath {
    # Obtener la ruta del script de forma robusta
    $scriptRoot = if ($PSScriptRoot) { 
        [string]$PSScriptRoot 
    } elseif ($MyInvocation.MyCommand.Path) { 
        Split-Path -Parent $MyInvocation.MyCommand.Path 
    } else { 
        Get-Location 
    }
    
    # Asegurar que sea una string y no un array
    $root = [string]$scriptRoot
    
    # Lista de posibles nombres de CoreInfo
    $candidates = @(
        (Join-Path -Path $root -ChildPath 'Coreinfo64.exe'),
        (Join-Path -Path $root -ChildPath 'Coreinfo64a.exe'),
        (Join-Path -Path $root -ChildPath 'Coreinfo.exe')
    )
    
    foreach ($candidate in $candidates) { 
        if (Test-Path -Path $candidate) { 
            return $candidate 
        } 
    }
    return $null
}

# ===============================
#  VERIFICACION DE HERRAMIENTAS DISPONIBLES
# ===============================
function Show-AvailableTools {
    $tools = @()
    
    # Verificar CoreInfo
    $coreinfo = Get-CoreInfoPath
    if ($coreinfo) {
        $tools += "CoreInfo"
    }
    
    # Verificar RAMMap
    $rammap = Get-RAMMapPath
    if ($rammap) {
        $tools += "RAMMap"
    }
    
    # Verificar EmptyStandbyList
    $emptyStandby = Join-Path $PSScriptRoot 'EmptyStandbyList.exe'
    if (Test-Path $emptyStandby) {
        $tools += "EmptyStandbyList"
    }
    
    if ($tools.Count -gt 0) {
        Write-Host "[TOOLS] Detectado: $($tools -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "[TOOLS] Sin herramientas Sysinternals - Modo basico" -ForegroundColor Yellow
    }
}

# Mostrar herramientas disponibles
Show-AvailableTools

# ===============================
#  SECCION 3: FUNCIONES Y LOGICA DE PLAN DE ENERGIA
# ===============================
function Get-CurrentPowerPlan {
    try {
        # Metodo 1: powercfg /getactivescheme con output limpio
        $output = & powercfg.exe /getactivescheme 2>$null
        if ($output -and $output -match 'GUID: ([a-fA-F0-9\-]+)') {
            Write-Host "[INFO] Plan de energia actual detectado: $($matches[1])"
            return $matches[1]
        }
        
        # Metodo 2: usar WMI Win32_PowerPlan
        $activePlan = Get-WmiObject -Namespace "root\cimv2\power" -Class Win32_PowerPlan -ErrorAction SilentlyContinue | Where-Object { $_.IsActive -eq $true }
        if ($activePlan -and $activePlan.InstanceID) {
            # Extraer GUID del InstanceID (formato: Microsoft:PowerPlan\{GUID})
            if ($activePlan.InstanceID -match '\{([a-fA-F0-9\-]+)\}') {
                Write-Host "[INFO] Plan de energia actual detectado via WMI: $($matches[1])"
                return $matches[1]
            }
        }
        
        # Metodo 3: leer directamente del registro
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
        $activeScheme = Get-ItemProperty -Path $regPath -Name "ActivePowerScheme" -ErrorAction SilentlyContinue
        if ($activeScheme -and $activeScheme.ActivePowerScheme) {
            $guid = $activeScheme.ActivePowerScheme.ToString().Trim('{}')
            if ($guid -match '^[a-fA-F0-9\-]+$') {
                Write-Host "[INFO] Plan de energia actual detectado via registro: $guid"
                return $guid
            }
        }
        
        # Metodo 4: powercfg /list y buscar activo
        $listOutput = & powercfg.exe /list 2>$null
        if ($listOutput) {
            $activeLines = $listOutput | Where-Object { $_ -match '\*' -and $_ -match 'GUID' }
            if ($activeLines -and $activeLines -match '([a-fA-F0-9\-]+)') {
                Write-Host "[INFO] Plan de energia actual detectado via list: $($matches[1])"
                return $matches[1]
            }
        }
        
        Write-Host "[WARN] No se pudo obtener el plan de energia actual con ningun metodo."
        return $null
    } catch {
        Write-Host "[WARN] Error al obtener plan de energia actual: $($_.Exception.Message)"
        return $null
    }
}

function Set-PowerPlanByGuid($guid) {
    if ($null -ne $guid) {
        Write-Host "[INFO] Cambiando plan de energia a GUID: $guid"
        powercfg /setactive $guid | Out-Null
    }
}

function Get-HighPerformancePlanGuid {
    $output = powercfg /list 2>&1
    foreach ($line in $output) {
        if ($line -match 'GUID: ([a-fA-F0-9\-]+).*(Alto rendimiento|High performance)') {
            return $matches[1]
        }
    }
    # GUID estandar de Alto rendimiento
    $stdGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    $output2 = powercfg /list 2>&1
    if ($output2 -match $stdGuid) {
        return $stdGuid
    }
    Write-Host "[WARN] No se encontro el plan de Alto rendimiento."
    return $null
}

# Guardar plan de energia actual
$originalPlan = Get-CurrentPowerPlan
if ($null -eq $originalPlan) {
    Write-Host "[WARN] No se pudo obtener el plan de energia actual. Se usara el GUID estandar para Alto rendimiento."
}
# Obtener GUID de Alto rendimiento
$highPerfPlan = Get-HighPerformancePlanGuid
if ($null -ne $highPerfPlan -and $originalPlan -ne $highPerfPlan) {
    Write-Host "[INFO] Cambiando a plan de energia Alto rendimiento..."
    Set-PowerPlanByGuid $highPerfPlan
}

# ===============================
#  SECCION 3B: OPTIMIZACION DE SERVICIOS Y PROCESOS
# ===============================
function Stop-ProcessesForGaming {
    # Procesos de utilidades, multimedia, Xbox, widgets, apps preinstaladas, etc.
    $processes = @(
        # Utilidades de fabricante y bloatware
        'LenovoUtilityService','FnHotkeyCapsLKNumLK','FnHotkeyUtility','DSAService','DSATray',
        # Apps en la nube y sincronizacion
        'OneDrive','OneDriveSetup','GrooveMusic','Skype',
        # Widgets y shell
        'PhoneExperienceHost','Widgets','WidgetService','ShellExperienceHost','StartMenuExperienceHost',
        # Navegadores y webview
        'msedgewebview2','msedge',
        # Multimedia y apps de Windows
        'AdobeCollabSync','Calculator','Microsoft.Photos','Video.UI','Movies&TV',
        # Intel y graficos
        'IntelGraphicsSoftware','igfxEMN',
        # Juegos y Xbox
        'Windows.Gaming.Input','gamingservices','gamingservicesnet','GameBar','XboxAppServices','XboxApp','XboxGameOverlay','XboxGamingOverlay','XboxPcApp','XboxSpeechToTextOverlay',
        # Otros procesos comunes
        'YourPhone','RuntimeBroker','BackgroundTransferHost','RemindersServer','SearchUI','SearchIndexer','OfficeClickToRun','MixedRealityPortal','Wmpnetwk'
    )
    $closedCount = 0
    foreach ($proc in $processes) {
        $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($found) {
            try {
                Stop-Process -Id $found.Id -Force -ErrorAction SilentlyContinue
                $closedCount++
            } catch {
                # Silencioso
            }
        }
    }
    if ($closedCount -gt 0) {
        Write-Host "[CLEANUP] $closedCount procesos innecesarios cerrados" -ForegroundColor Green
    }
}

$stoppedServicesForGaming = @()
function Stop-ServicesForGaming {
    # Servicios de impresion, multimedia, bloatware, Xbox, telemetria, etc. (sin tocar seguridad, red ni internet)
    $services = @(
        # Telemetria y diagnostico
        'DiagTrack','PcaSvc',
        # Indexado y busqueda
        'WSearch',
        # Servicios de impresion y fax
        'Spooler','Fax',
        # Multimedia y compatibilidad
        'WMPNetworkSvc','HomeGroupListener','HomeGroupProvider','FrameServer','WbioSrvc',
        # Servicios de Xbox y juegos
        'XblGameSave','XboxGipSvc','XboxNetApiSvc','GameDVR','GameInput','GamingServices','GamingServicesNet',
        # Utilidades de fabricante
        'LenovoUtilityService','FnHotkeyCapsLKNumLK','FnHotkeyUtility',
        # Otros
        'TrkWks','DPS','BITS','UsoSvc','SysMain','RetailDemo','MapsBroker','icssvc','PerceptionSimulation','PerceptionSvc','wisvc'
    )
    $stoppedCount = 0
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            try {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                $script:stoppedServicesForGaming += $svc
                $stoppedCount++
            } catch {
                # Silencioso
            }
        }
        # Deshabilitar SysMain y Superfetch si aplica
        if ($svc -eq 'SysMain') {
            try {
                Set-Service -Name 'SysMain' -StartupType Disabled -ErrorAction SilentlyContinue
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Value 0 -ErrorAction SilentlyContinue
            } catch {
                # Silencioso
            }
        }
    }
    if ($stoppedCount -gt 0) {
        Write-Host "[CLEANUP] $stoppedCount servicios innecesarios detenidos" -ForegroundColor Green
    }
}

function Restore-ServicesForGaming {
    if ($script:stoppedServicesForGaming.Count -gt 0) {
        $restoredCount = 0
        foreach ($svc in $script:stoppedServicesForGaming) {
            try {
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                $restoredCount++
            } catch {
                # Silencioso
            }
        }
        Write-Host "[CLEANUP] $restoredCount servicios restaurados" -ForegroundColor Green
    }
}

# ===============================
#  SECCION 3D: LIMPIEZA DE ARCHIVOS TEMPORALES Y CACHE
# ===============================
function Clear-TempFiles {
    $tempPaths = @(
        "$env:TEMP",
        "$env:WINDIR\Temp",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    )
    $cleanedFiles = 0
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
                $files | ForEach-Object {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        $cleanedFiles++
                    } catch {
                        # Silencioso
                    }
                }
            } catch {
                # Silencioso
            }
        }
    }
    if ($cleanedFiles -gt 0) {
        Write-Host "[CLEANUP] $cleanedFiles archivos temporales eliminados" -ForegroundColor Green
    }
}

function Clear-ExplorerCache {
    try {
        $iconCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*"
        $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache*"
        Remove-Item $iconCache -Force -ErrorAction SilentlyContinue
        Remove-Item $thumbCache -Force -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Cache de Explorer limpiado" -ForegroundColor Green
    } catch {
        # Silencioso
    }
}

function Clear-Prefetch {
    try {
        $prefetchPath = "$env:WINDIR\Prefetch"
        if (Test-Path $prefetchPath) {
            $cleanedFiles = 0
            Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        $cleanedFiles++
                    } catch {
                        # Silencioso
                    }
                }
            if ($cleanedFiles -gt 0) {
                Write-Host "[CLEANUP] $cleanedFiles archivos prefetch eliminados" -ForegroundColor Green
            }
        }
    } catch {
        # Silencioso
    }
}

# ===============================
#  SECCION 3E: LIBERACION DE MEMORIA RAM
# ===============================
function Show-MemoryOptimizationInfo {
    $rammap = Get-RAMMapPath
    $emptyStandby = Join-Path $PSScriptRoot 'EmptyStandbyList.exe'
    
    $methods = @()
    if ($rammap) { $methods += "RAMMap" }
    if (Test-Path $emptyStandby) { $methods += "EmptyStandbyList" }
    $methods += ".NET GC"
    
    Write-Host "[MEMORY] Metodos disponibles: $($methods -join ', ')" -ForegroundColor Cyan
}

function Clear-Memory {
    $success = $false
    
    # Metodo 1: Intentar usar RAMMap.exe
    $ramMap = Get-RAMMapPath
    if ($ramMap) {
        try {
            & $ramMap -Et -Es -Em -Ep 2>$null | Out-Null
            Write-Host "[MEMORY] RAMMap: Working sets y standby list limpiados" -ForegroundColor Green
            $success = $true
        } catch {
            # Fallback silencioso
        }
    }
    
    # Metodo 2: Fallback a EmptyStandbyList
    if (-not $success) {
        $emptyStandby = Join-Path $PSScriptRoot 'EmptyStandbyList.exe'
        if (Test-Path $emptyStandby) {
            try {
                & $emptyStandby standbylist 2>$null | Out-Null
                Write-Host "[MEMORY] EmptyStandbyList: Standby list limpiado" -ForegroundColor Green
                $success = $true
            } catch {
                # Fallback silencioso
            }
        }
    }
    
    # Metodo 3: Siempre ejecutar .NET GC
    try {
        [System.GC]::Collect(2, [System.GCCollectionMode]::Forced)
        [System.GC]::WaitForPendingFinalizers()
        if (-not $success) {
            Write-Host "[MEMORY] .NET Garbage Collector ejecutado" -ForegroundColor Green
        }
    } catch {
        # Silencioso
    }
    
    # Metodo 4: API de Windows (cache del sistema)
    try {
        $systemCacheSignature = @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetSystemFileCacheSize(
    IntPtr MinimumFileCacheSize,
    IntPtr MaximumFileCacheSize,
    int Flags
);
'@
        Add-Type -MemberDefinition $systemCacheSignature -Name "SystemCache" -Namespace Win32 -ErrorAction SilentlyContinue
        [Win32.SystemCache]::SetSystemFileCacheSize([IntPtr]::Zero, [IntPtr]::Zero, 4) | Out-Null
    } catch {
        # Silencioso
    }
}
Clear-Memory

# ===============================
#  SECCION 3F: OPTIMIZACION DE REGISTRO PARA GRAFICOS Y MULTIMEDIA
# ===============================
function Backup-RegistryGaming {
    Write-Host "[INFO] Respaldando configuraciones de registro relevantes..."
    $backupPath = "$env:TEMP\\CS2Optimizer_Backup"
    if (!(Test-Path $backupPath)) { New-Item -Path $backupPath -ItemType Directory | Out-Null }
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "$backupPath\multimedia_profile.reg" /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "$backupPath\graphics_drivers.reg" /y | Out-Null
    Write-Host "[INFO] Backups de registro guardados en: $backupPath"
}

function Get-GPUVendor {
    $gpu = Get-WmiObject Win32_VideoController | Select-Object -First 1 -ExpandProperty Name
    if ($gpu -match 'NVIDIA') { return 'NVIDIA' }
    elseif ($gpu -match 'AMD' -or $gpu -match 'Radeon') { return 'AMD' }
    elseif ($gpu -match 'Intel') { return 'Intel' }
    else { return 'Desconocido' }
}

function Get-CS2ExePath {
    # Intenta detectar la ruta de Steam desde el registro
    $steamPath = $null
    $cs2Exe = $null
    try {
        $steamReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' -ErrorAction SilentlyContinue
        if ($steamReg -and $steamReg.InstallPath) {
            $steamPath = $steamReg.InstallPath
        } else {
            $steamRegCU = Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -ErrorAction SilentlyContinue
            if ($steamRegCU -and $steamRegCU.SteamPath) {
                $steamPath = $steamRegCU.SteamPath
            }
        }
    } catch {}
    if ($steamPath) {
        # Leer libraryfolders.vdf para encontrar todas las librerías de Steam
        $libraryVdf = Join-Path $steamPath 'steamapps\libraryfolders.vdf'
        $libraryPaths = @($steamPath)
        if (Test-Path $libraryVdf) {
            $lines = Get-Content $libraryVdf -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '"path"\s+"([^"]+)"') {
                    $lib = $matches[1]
                    if ($lib -and !( $libraryPaths -contains $lib )) {
                        $libraryPaths += $lib
                    }
                }
            }
        }
        # Buscar cs2.exe en cada librería
        foreach ($libPath in $libraryPaths) {
            $cs2Path = Join-Path $libPath 'steamapps\common\Counter-Strike Global Offensive\cs2.exe'
            if (Test-Path $cs2Path) {
                $cs2Exe = $cs2Path
                break
            }
        }
    }
    return $cs2Exe
}

function Get-CS16ExePath {
    # Intenta detectar la ruta de CS 1.6 (hl.exe) en Steam
    $steamPath = $null
    $cs16Exe = $null
    try {
        $steamReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' -ErrorAction SilentlyContinue
        if ($steamReg -and $steamReg.InstallPath) {
            $steamPath = $steamReg.InstallPath
        } else {
            $steamRegCU = Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -ErrorAction SilentlyContinue
            if ($steamRegCU -and $steamRegCU.SteamPath) {
                $steamPath = $steamRegCU.SteamPath
            }
        }
    } catch {}
    if ($steamPath) {
        $libraryVdf = Join-Path $steamPath 'steamapps\libraryfolders.vdf'
        $libraryPaths = @($steamPath)
        if (Test-Path $libraryVdf) {
            $lines = Get-Content $libraryVdf -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '"path"\s+"([^"]+)"') {
                    $lib = $matches[1]
                    if ($lib -and !( $libraryPaths -contains $lib )) {
                        $libraryPaths += $lib
                    }
                }
            }
        }
        foreach ($libPath in $libraryPaths) {
            $cs16Path = Join-Path $libPath 'steamapps\common\Half-Life\hl.exe'
            if (Test-Path $cs16Path) {
                $cs16Exe = $cs16Path
                break
            }
        }
    }
    return $cs16Exe
}

function Optimize-GraphicsAndMultimedia {
    $gpuVendor = Get-GPUVendor
    Write-Host "Detectado GPU: $gpuVendor"
    Write-Host "Aplicando optimizaciones de gráficos y multimedia..."
    if ($gpuVendor -eq 'Intel') {
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 2 /f | Out-Null
        reg add "HKCU\Software\Intel\Iris" /v "CS2Optimization" /t REG_DWORD /d 1 /f | Out-Null
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f | Out-Null
    } elseif ($gpuVendor -eq 'NVIDIA') {
        # Detectar ruta real de cs2.exe
        $exePath = Get-CS2ExePath
        if ($exePath) {
            reg add "HKLM\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "$exePath" /t REG_SZ /d "GpuPreference=2;" /f | Out-Null
        }
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f | Out-Null
        reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 0 /f | Out-Null
    } elseif ($gpuVendor -eq 'AMD') {
        $ulpsPaths = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '{4d36e968-e325-11ce-bfc1-08002be10318}' }
        foreach ($path in $ulpsPaths) {
            try {
                Set-ItemProperty -Path $path.PSPath -Name "EnableUlps" -Value 0 -ErrorAction SilentlyContinue
            } catch {}
        }
        reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f | Out-Null
    }
    # Tweaks universales
    reg add "HKCU\Software\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 20 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 10 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f | Out-Null
    Write-Host "Optimización de gráficos y multimedia aplicada."
}

function Restore-RegistryGaming {
    Write-Host "[INFO] Restaurando configuraciones de registro..."
    $backupPath = "$env:TEMP\\CS2Optimizer_Backup"
    if (Test-Path "$backupPath\multimedia_profile.reg") {
        reg import "$backupPath\multimedia_profile.reg" | Out-Null
        Write-Host "[INFO] Perfil multimedia restaurado."
    }
    if (Test-Path "$backupPath\graphics_drivers.reg") {
        reg import "$backupPath\graphics_drivers.reg" | Out-Null
        Write-Host "[INFO] Configuración de gráficos restaurada."
    }
}

# ===============================
#  SECCION 3G: OPTIMIZACIONES AVANZADAS TEMPORALES (SEGURAS)
# ===============================

function Set-AdvancedPerformanceOptimizations {
    $optimizationsApplied = @()
    
    # 1. Optimizar Timer Resolution (TEMPORAL - se revierte al cerrar)
    try {
        $signature = @'
[DllImport("winmm.dll", EntryPoint="timeBeginPeriod")]
public static extern uint TimeBeginPeriod(uint uPeriod);

[DllImport("winmm.dll", EntryPoint="timeEndPeriod")]  
public static extern uint TimeEndPeriod(uint uPeriod);

[DllImport("kernel32.dll")]
public static extern bool SetProcessAffinityMask(IntPtr hProcess, UIntPtr dwProcessAffinityMask);

[DllImport("kernel32.dll")]
public static extern IntPtr GetCurrentProcess();
'@
        Add-Type -MemberDefinition $signature -Name "PerformanceOptimizer" -Namespace Win32
        
        $result = [Win32.PerformanceOptimizer]::TimeBeginPeriod(1)
        if ($result -eq 0) {
            $optimizationsApplied += "Timer Resolution (1ms)"
            $script:timerOptimized = $true
        }
    } catch {
        # Silencioso
    }
    
    # 2. Optimizar Scheduler de Windows
    try {
        $currentSeparation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue
        if ($currentSeparation) {
            $script:originalPrioritySeparation = $currentSeparation.Win32PrioritySeparation
        }
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord
        $optimizationsApplied += "Scheduler Gaming"
        $script:schedulerOptimized = $true
    } catch {
        # Silencioso
    }
    
    # 3. Optimizar Memory Management
    try {
        $memMgmt = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction SilentlyContinue
        if ($memMgmt) {
            $script:originalLargeSystemCache = $memMgmt.LargeSystemCache
            $script:originalDisablePagingExecutive = $memMgmt.DisablePagingExecutive
        }
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Type DWord
        $optimizationsApplied += "Memory Management"
        $script:memoryOptimized = $true
    } catch {
        # Silencioso
    }
    
    # 4. Configurar Thread Priorities
    try {
        $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
        $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High
        $optimizationsApplied += "Process Priority"
    } catch {
        # Silencioso
    }
    
    if ($optimizationsApplied.Count -gt 0) {
        Write-Host "[SYSTEM] Aplicado: $($optimizationsApplied -join ', ')" -ForegroundColor Green
    }
}

function Restore-AdvancedPerformanceOptimizations {
    $restoredItems = @()
    
    # 1. Restaurar Timer Resolution
    if ($script:timerOptimized) {
        try {
            [Win32.PerformanceOptimizer]::TimeEndPeriod(1)
            $restoredItems += "Timer Resolution"
        } catch {
            # Silencioso
        }
    }
    
    # 2. Restaurar Scheduler
    if ($script:schedulerOptimized -and $script:originalPrioritySeparation) {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value $script:originalPrioritySeparation -Type DWord
            $restoredItems += "Scheduler"
        } catch {
            # Silencioso
        }
    }
    
    # 3. Restaurar Memory Management
    if ($script:memoryOptimized) {
        try {
            if ($null -ne $script:originalLargeSystemCache) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value $script:originalLargeSystemCache -Type DWord
            }
            if ($null -ne $script:originalDisablePagingExecutive) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value $script:originalDisablePagingExecutive -Type DWord
            }
            $restoredItems += "Memory Management"
        } catch {
            # Silencioso
        }
    }
    
    if ($restoredItems.Count -gt 0) {
        Write-Host "[SYSTEM] Restaurado: $($restoredItems -join ', ')" -ForegroundColor Green
    }
}

# Variables para tracking de optimizaciones
$script:timerOptimized = $false
$script:schedulerOptimized = $false
$script:memoryOptimized = $false
$script:originalPrioritySeparation = $null
$script:originalLargeSystemCache = $null
$script:originalDisablePagingExecutive = $null

# Aplicar optimizaciones avanzadas
Set-AdvancedPerformanceOptimizations

# ===============================
#  SECCION 4: BLOQUE PRINCIPAL DE OPTIMIZACION (AQUI VA EL JUEGO)
# ===============================
Write-Host "[INFO] Modo Debug: $DebugMode"

function Wait-ForGameProcess {
    param(
        [string]$processName,
        [string]$displayName
    )
    Write-Host "[INFO] Esperando a que $displayName inicie... (ejecutalo manualmente desde Steam)"
    while ($true) {
        $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "[INFO] $displayName detectado (PID: $($proc.Id)). Aplicando prioridad y afinidad..."
            try {
                Show-AffinityInfo -mode $AffinityMode
                $affinity = Get-ProcessorAffinityMask
                $proc.ProcessorAffinity = $affinity
                $proc.PriorityClass = 'High'
                Write-Host "[INFO] Afinidad ($affinity) y prioridad aplicadas a $displayName."
            } catch {
                Write-Host ('[WARN] No se pudo establecer afinidad/prioridad para {0}: {1}' -f $displayName, $_)
            }
            Write-Host "[INFO] Esperando a que $displayName finalice..."
            $proc.WaitForExit()
            Write-Host "[INFO] $displayName se cerro correctamente."
            break
        }
        Start-Sleep -Seconds 2
    }
}

# ===============================
#  FUNCIONES DE ROBUSTEZ Y UTILIDAD GENERAL (MEJORADAS)
# ===============================

function Get-ProcessorAffinityMask {
    # Devuelve una máscara óptima según el modo y la topología detectada
    try {
        return Get-OptimalAffinityMask -mode $AffinityMode
    } catch {
        Write-Log -Message "Fallo en Get-OptimalAffinityMask, usando mascara estandar." -Level 'WARN'
        $cpuCount = [Environment]::ProcessorCount
        if ($cpuCount -gt 1) {
            # Todos los bits a 1 excepto el menos significativo (nucleo 0)
            return [int]([math]::Pow(2, $cpuCount) - 2)
        } elseif ($cpuCount -eq 1) {
            # Solo un nucleo, no se puede omitir el 0
            return 1
        } else {
            return 0xFFFFFFFE
        }
    }
}

function Test-Admin {
    # Verifica si el script corre como administrador
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        return $isAdmin
    } catch {
        Write-Log -Message "No se pudo verificar privilegios de administrador." -Level 'WARN'
        return $false
    }
}

function Test-ProcessExists {
    param(
        [string]$processName
    )
    try {
        $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        return ($null -ne $proc)
    } catch {
        Write-Log -Message "Error comprobando proceso $processName" -Level 'WARN'
        return $false
    }
}

function Test-RegistryKeyExists {
    param(
        [string]$keyPath
    )
    try {
        if (Test-Path $keyPath) { return $true } else { return $false }
    } catch {
        Write-Log -Message "Error comprobando clave de registro $keyPath" -Level 'WARN'
        return $false
    }
}

function Test-FileExists {
    param(
        [string]$filePath
    )
    try {
        if (Test-Path $filePath) { return $true } else { return $false }
    } catch {
        Write-Log -Message "Error comprobando archivo $filePath" -Level 'WARN'
        return $false
    }
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ("[$Level] $timestamp $Message")
}

function Invoke-SafeCommand {
    param(
        [scriptblock]$Script,
        [string]$ErrorMessage = 'Error ejecutando comando',
        [string]$Level = 'WARN'
    )
    try {
        & $Script
        return $true
    } catch {
        Write-Log -Message $ErrorMessage -Level $Level
        return $false
    }
}

function Stop-SafeProcess {
    param(
        [string]$Name
    )
    Invoke-SafeCommand -Script { Stop-Process -Name $Name -Force -ErrorAction Stop } -ErrorMessage "No se pudo cerrar proceso: $Name" -Level 'DEBUG'
}

function Stop-SafeService {
    param(
        [string]$Name
    )
    Invoke-SafeCommand -Script { Stop-Service -Name $Name -Force -ErrorAction Stop } -ErrorMessage "No se pudo detener servicio: $Name" -Level 'DEBUG'
}

function Start-SafeService {
    param(
        [string]$Name
    )
    Invoke-SafeCommand -Script { Start-Service -Name $Name -ErrorAction Stop } -ErrorMessage "No se pudo restaurar servicio: $Name" -Level 'DEBUG'
}

function Remove-SafeItem {
    param(
        [string]$Path
    )
    Invoke-SafeCommand -Script { Remove-Item $Path -Force -ErrorAction Stop } -ErrorMessage "No se pudo eliminar: $Path" -Level 'DEBUG'
}

function Set-SafeItemProperty {
    param(
        [string]$Path, [string]$Name, $Value
    )
    Invoke-SafeCommand -Script { Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop } -ErrorMessage "No se pudo modificar propiedad $Name en $Path" -Level 'DEBUG'
}

function Disable-FSO-HAGS-FocusAssist {
    # Desactiva Fullscreen Optimizations para cs2.exe, HAGS y notificaciones/Focus Assist
    Write-Log -Message "Aplicando tweaks extra: Fullscreen Optimizations, HAGS, Focus Assist, notificaciones..."
    # 1. Desactivar Fullscreen Optimizations para cs2.exe
    $cs2Path = Get-CS2ExePath
    if ($cs2Path -and (Test-Path $cs2Path)) {
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
            New-Item -Path $regPath -Force | Out-Null
            Set-ItemProperty -Path $regPath -Name $cs2Path -Value '~ DISABLEDXMAXIMIZEDWINDOWEDMODE' -Force
            Write-Log -Message "Fullscreen Optimizations desactivado para $cs2Path"
        } catch {
            Write-Log -Message "No se pudo desactivar Fullscreen Optimizations para $cs2Path" -Level 'WARN'
        }
    } else {
        Write-Log -Message "No se encontró cs2.exe para desactivar Fullscreen Optimizations" -Level 'WARN'
    }
    # 2. Desactivar HAGS (Hardware Accelerated GPU Scheduling)
    try {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode' -Value 1 -Type DWord -Force
        Write-Log -Message "HAGS (HwSchMode) desactivado en el registro."
    } catch {
        Write-Log -Message "No se pudo desactivar HAGS (HwSchMode) en el registro" -Level 'WARN'
    }
    # 3. Desactivar notificaciones y Focus Assist
    try {
        # Notificaciones
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' -Value 0 -Type DWord -Force
        # Focus Assist: 0 = Off
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name 'FocusAssist' -Value 0 -Type DWord -Force
        Write-Log -Message "Notificaciones y Focus Assist desactivados."
    } catch {
        Write-Log -Message "No se pudo desactivar notificaciones o Focus Assist" -Level 'WARN'
    }
}

# ===============================
#  FUNCIONES DE TOPOLOGÍA Y AFINIDAD AVANZADA (COREINFO)
# ===============================
function Get-CoreInfoTopology {
    try {
        # Usar caché si está disponible y válida
        if ($script:CoreInfoCacheValid -and $script:CoreInfoCache) {
            $output = $script:CoreInfoCache
        } else {
            $coreinfo = Get-CoreInfoPath
            if (-not $coreinfo) { 
                Write-Log -Message "CoreInfo no encontrado en la ruta del script" -Level 'WARN'
                return $null 
            }
            
            Write-Log -Message "Ejecutando CoreInfo desde: $coreinfo" -Level 'INFO'
            
            # Ejecutar CoreInfo y capturar toda la salida
            $output = & $coreinfo -nobanner 2>&1
            
            # Guardar en caché
            $script:CoreInfoCache = $output
            $script:CoreInfoCacheValid = $true
        }
        if (-not $output) { 
            Write-Log -Message "CoreInfo no produjo salida" -Level 'WARN'
            return $null 
        }
        
        # Debug: Mostrar las primeras lineas de salida de CoreInfo
        if ($DebugMode) {
            Write-Log -Message "Salida de CoreInfo (primeras 10 lineas):" -Level 'DEBUG'
            $debugLines = $output | Select-Object -First 10
            foreach ($line in $debugLines) {
                Write-Log -Message "  > $line" -Level 'DEBUG'
            }
        }
        
        $topology = @{
            'isIntel' = $false
            'isAMD' = $false
            'cores' = @()
            'totalCores' = 0
        }
        
        # Detectar fabricante
        $outputText = $output -join "`n"
        $topology['isIntel'] = $outputText -match 'Intel'
        $topology['isAMD'] = $outputText -match 'AMD'
        
        if ($topology['isIntel']) {
            Write-Log -Message "Procesador Intel detectado" -Level 'INFO'
            
            # Buscar el patron "Logical to Physical Processor Map" para CPUs pre-hybrid
            $inPhysicalMap = $false
            $parsedCores = $false
            
            foreach ($line in $output) {
                if ($line -match 'Logical to Physical Processor Map:') {
                    $inPhysicalMap = $true
                    Write-Log -Message "Detectado mapa de procesadores logicos a fisicos" -Level 'INFO'
                    continue
                }
                
                if ($inPhysicalMap) {
                    # Buscar lineas con el patron de mapeo: **------ Physical Processor 0 (Hyperthreaded)
                    if ($line -match '^([*\-]+)\s+Physical Processor\s+(\d+)(\s+\(.*\))?') {
                        $pattern = $matches[1]
                        $physicalId = [int]$matches[2]
                        $parsedCores = $true
                        
                        Write-Log -Message "Procesador fisico $physicalId con patron: '$pattern'" -Level 'DEBUG'
                        
                        # Contar posiciones de * para determinar cores logicos
                        for ($i = 0; $i -lt $pattern.Length; $i++) {
                            if ($pattern[$i] -eq '*') {
                                $topology['cores'] += @{ 
                                    id = $i
                                    type = 'Performance'  # Para CPUs pre-hybrid, todos son performance
                                    physicalCore = $physicalId
                                    isPerformance = $true
                                }
                                Write-Log -Message "Core logico $i asignado a procesador fisico $physicalId" -Level 'DEBUG'
                            }
                        }
                    } elseif ($line -match '^\s*$' -or $line -match '^[A-Z].*:') {
                        # Linea vacia o nueva seccion con : - salir del mapa fisico
                        if ($parsedCores) {
                            $inPhysicalMap = $false
                        }
                    }
                }
            }
            
            # Si no se encontró el patron de mapeo, buscar hybrid cores (12gen+)
            if (-not $parsedCores) {
                Write-Log -Message "No se encontro mapa fisico, buscando arquitectura hybrid" -Level 'INFO'
                foreach ($line in $output) {
                    if ($line -match 'Core\s+(\d+):\s+.*Type\s+(\w+)') {
                        $coreId = [int]$matches[1]
                        $coreType = $matches[2]
                        $topology['cores'] += @{ 
                            id = $coreId
                            type = $coreType
                            isPerformance = ($coreType -eq 'Performance' -or $coreType -eq 'P')
                        }
                        $parsedCores = $true
                    }
                }
            }
            
            # Fallback si no se pudo parsear nada
            if (-not $parsedCores) {
                Write-Log -Message "Usando metodo fallback para Intel" -Level 'INFO'
                $cpuCount = [Environment]::ProcessorCount
                for ($i = 0; $i -lt $cpuCount; $i++) {
                    $topology['cores'] += @{
                        id = $i
                        type = 'Performance'
                        physicalCore = [math]::Floor($i / 2)  # Asumir hyperthreading
                        isPerformance = $true
                    }
                }
                $parsedCores = $true
            }
        } elseif ($topology['isAMD']) {
            Write-Log -Message "Procesador AMD detectado" -Level 'INFO'
            # Buscar información de CCDs con patrones más amplios
            foreach ($line in $output) {
                if ($line -match 'CPU\s+(\d+)\s+.*Node\s*(\d+).*CCX\s*(\d+)') {
                    $cpuId = [int]$matches[1]
                    $node = [int]$matches[2]
                    $ccx = [int]$matches[3]
                    $topology['cores'] += @{ 
                        id = $cpuId
                        node = $node
                        ccx = $ccx
                        isFirstCCD = ($ccx -eq 0)
                    }
                } elseif ($line -match 'CPU\s+(\d+)') {
                    # Patron alternativo para AMD
                    $cpuId = [int]$matches[1]
                    $topology['cores'] += @{ 
                        id = $cpuId
                        node = 0
                        ccx = 0
                        isFirstCCD = $true
                    }
                }
            }
        } else {
            Write-Log -Message "Fabricante no identificado, usando patron generico" -Level 'INFO'
            # Patron generico para cualquier CPU
            foreach ($line in $output) {
                if ($line -match 'CPU\s+(\d+)' -or $line -match 'Core\s+(\d+)' -or $line -match '\s+(\d+)\s+') {
                    $coreId = [int]$matches[1]
                    if ($coreId -ge 0 -and $coreId -lt 64) {  # Validar ID razonable
                        $topology['cores'] += @{ 
                            id = $coreId
                            type = 'Generic'
                            isPerformance = $true
                        }
                    }
                }
            }
        }
        
        # Remover duplicados y ordenar cores
        $uniqueCores = @()
        $seenIds = @()
        foreach ($core in $topology['cores']) {
            if ($seenIds -notcontains $core.id) {
                $uniqueCores += $core
                $seenIds += $core.id
            }
        }
        $topology['cores'] = $uniqueCores | Sort-Object { $_.id }
        $topology['totalCores'] = $topology['cores'].Count
        
        Write-Log -Message "Topologia detectada: $($topology['totalCores']) nucleos" -Level 'INFO'
        
        # Si no se detectaron cores, intentar fallback con info basica del sistema
        if ($topology['totalCores'] -eq 0) {
            Write-Log -Message "No se detectaron cores con CoreInfo, generando topologia basica" -Level 'WARN'
            $cpuCount = [Environment]::ProcessorCount
            for ($i = 0; $i -lt $cpuCount; $i++) {
                $topology['cores'] += @{
                    id = $i
                    type = 'Fallback'
                    isPerformance = $true
                }
            }
            $topology['totalCores'] = $cpuCount
            Write-Log -Message "Topologia fallback generada: $($topology['totalCores']) nucleos" -Level 'INFO'
        }
        
        return $topology
    }
    catch {
        Write-Log -Message "Error al obtener topología de CoreInfo: $($_.Exception.Message)" -Level 'ERROR'
        return $null
    }
}

function Get-OptimalAffinityMask {
    param(
        [string]$mode = 'auto'
    )
    # Si el modo es auto, intentar usar CoreInfo para optimización avanzada
    if ($mode -eq 'auto') {
        $coreinfo = Get-CoreInfoPath
        if ($coreinfo) {
            # Forzar uso de caché si existe
            if (-not $script:CoreInfoCacheValid -or -not $script:CoreInfoCache) {
                $null = Get-CoreInfoTopology  # Esto pobla el caché
            }
            $topo = Get-CoreInfoTopology
            if ($topo -and $topo['cores'].Count -gt 0) {
                $mask = 0
                if ($topo['isIntel']) {
                    $pCores = $topo['cores'] | Where-Object { $_.isPerformance -eq $true }
                    if ($pCores.Count -gt 0) {
                        Write-Log -Message "Usando P-cores de Intel: $($pCores.Count) nucleos" -Level 'INFO'
                        foreach ($core in $pCores) { 
                            $mask = $mask -bor (1 -shl $core.id) 
                        }
                        return $mask
                    }
                } elseif ($topo['isAMD']) {
                    $firstCCD = $topo['cores'] | Where-Object { $_.isFirstCCD -eq $true }
                    if ($firstCCD.Count -gt 0) {
                        Write-Log -Message "Usando primer CCD de AMD: $($firstCCD.Count) nucleos" -Level 'INFO'
                        foreach ($core in $firstCCD) { 
                            $mask = $mask -bor (1 -shl $core.id) 
                        }
                        return $mask
                    }
                }
                Write-Log -Message "Usando todos los nucleos detectados por CoreInfo" -Level 'INFO'
                foreach ($core in $topo['cores']) { 
                    $mask = $mask -bor (1 -shl $core.id) 
                }
                return $mask
            }
        }
    }
    
    # Fallback: método estándar basado en cantidad de procesadores
    Write-Log -Message "Usando metodo estandar de afinidad" -Level 'INFO'
    $cpuCount = [Environment]::ProcessorCount
    if ($cpuCount -gt 1) {
        # Excluir el último núcleo para el sistema
        return [int]([math]::Pow(2, $cpuCount) - 2)
    } elseif ($cpuCount -eq 1) {
        return 1
    } else {
        return 0xFFFFFFFE
    }
}

function Show-AffinityInfo {
    param(
        [string]$mode = 'auto'
    )
    
    $cpuCount = [Environment]::ProcessorCount
    
    if ($mode -eq 'auto') {
        $coreinfo = Get-CoreInfoPath
        if ($coreinfo) {
            if (-not $script:CoreInfoCacheValid -or -not $script:CoreInfoCache) {
                $null = Get-CoreInfoTopology
            }
            $topo = Get-CoreInfoTopology
            if ($topo -and $topo['cores'].Count -gt 0) {
                if ($topo['isIntel']) {
                    $pCores = $topo['cores'] | Where-Object { $_.isPerformance -eq $true }
                    $eCores = $topo['cores'] | Where-Object { $_.isPerformance -eq $false }
                    if ($pCores.Count -gt 0 -and $eCores.Count -gt 0) {
                        Write-Host "[CPU] Intel Hibrido: $($pCores.Count) P-cores + $($eCores.Count) E-cores (usando solo P-cores)" -ForegroundColor Cyan
                    } else {
                        Write-Host "[CPU] Intel: $cpuCount cores logicos" -ForegroundColor Cyan
                    }
                } elseif ($topo['isAMD']) {
                    $firstCCD = $topo['cores'] | Where-Object { $_.isFirstCCD -eq $true }
                    if ($firstCCD.Count -gt 0) {
                        Write-Host "[CPU] AMD: $cpuCount cores (usando primer CCD: $($firstCCD.Count) cores)" -ForegroundColor Cyan
                    } else {
                        Write-Host "[CPU] AMD: $cpuCount cores logicos" -ForegroundColor Cyan
                    }
                }
            } else {
                Write-Host "[CPU] $cpuCount cores logicos (topologia basica)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "[CPU] $cpuCount cores logicos (sin CoreInfo)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[CPU] $cpuCount cores logicos (modo estandar)" -ForegroundColor Cyan
    }
    
    # Mostrar máscara aplicada de forma concisa
    $mask = Get-OptimalAffinityMask -mode $mode
    $usedCores = @()
    for ($i = 0; $i -lt $cpuCount; $i++) { 
        if ($mask -band (1 -shl $i)) { 
            $usedCores += $i 
        } 
    }
    
    Write-Host "[AFFINITY] Cores asignados: [$($usedCores -join ',')] | Mascara: 0x$($mask.ToString('X'))" -ForegroundColor Green
}

# Ejecutar optimizaciones iniciales
Stop-ProcessesForGaming
Stop-ServicesForGaming
Clear-TempFiles
Clear-ExplorerCache
Clear-Prefetch
Show-MemoryOptimizationInfo
Clear-Memory

# Llamar a la función de tweaks extra antes de esperar el proceso del juego
Disable-FSO-HAGS-FocusAssist

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "   SISTEMA OPTIMIZADO - LISTO PARA GAMING" -ForegroundColor White
Write-Host "==============================================" -ForegroundColor Green

if ($DebugMode) {
    Wait-ForGameProcess -processName 'hl' -displayName 'CS 1.6 (hl.exe)'
} else {
    Wait-ForGameProcess -processName 'peak' -displayName 'Peak (peak.exe)'
}

# Restaurar plan de energía original
if ($null -ne $originalPlan -and $originalPlan -ne $highPerfPlan) {
    Write-Host "[POWER] Plan de energia restaurado" -ForegroundColor Green
    Set-PowerPlanByGuid $originalPlan
}

# Restaurar servicios detenidos
Restore-ServicesForGaming

# Restaurar optimizaciones avanzadas
Restore-AdvancedPerformanceOptimizations

# Restaurar configuraciones de registro al finalizar
Restore-RegistryGaming

# ===============================
#  FINALIZACION
# ===============================
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   OPTIMIZADOR CS2 LIGHT - FINALIZADO" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
$gameType = if ($DebugMode) { "CS 1.6" } else { "CS2" }
Write-Host "[COMPLETE] $gameType optimizado y sistema restaurado" -ForegroundColor Green
Write-Host "[EXIT] Presiona cualquier tecla para cerrar..." -ForegroundColor Gray
Read-Host