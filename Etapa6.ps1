# ===============================
#  ETAPA 6: OPTIMIZACIONES DE REGISTRO Y GRAFICOS
#  Aplica optimizaciones de registro y configuraciones gráficas
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
Write-Host "   ETAPA 6: OPTIMIZACIONES DE REGISTRO/GRAFICOS" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

# Variables globales para backup
$script:originalPrioritySeparation = $null
$script:originalLargeSystemCache = $null
$script:originalDisablePagingExecutive = $null
$script:registryBackup = @{}

# ===============================
#  FUNCIONES DE BACKUP Y RESTAURACION
# ===============================
function Backup-RegistryGaming {
    Write-Host "[REG] Creando backup de configuraciones de registro..." -ForegroundColor Green
    
    try {
        # Backup de configuraciones de rendimiento
        $perfKey = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
        if (Test-Path $perfKey) {
            $script:originalPrioritySeparation = Get-ItemProperty -Path $perfKey -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue
            $script:registryBackup["PrioritySeparation"] = $script:originalPrioritySeparation
        }
        
        # Backup de configuraciones de memoria
        $memKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $memKey) {
            $script:originalLargeSystemCache = Get-ItemProperty -Path $memKey -Name "LargeSystemCache" -ErrorAction SilentlyContinue
            $script:originalDisablePagingExecutive = Get-ItemProperty -Path $memKey -Name "DisablePagingExecutive" -ErrorAction SilentlyContinue
            $script:registryBackup["LargeSystemCache"] = $script:originalLargeSystemCache
            $script:registryBackup["DisablePagingExecutive"] = $script:originalDisablePagingExecutive
        }
        
        Write-Host "[REG] Backup de registro creado" -ForegroundColor Gray
        
    } catch {
        Write-Host "[WARN] Error creando backup de registro: $_" -ForegroundColor Yellow
    }
}

function Restore-RegistryGaming {
    Write-Host "[REG] Restaurando configuraciones de registro..." -ForegroundColor Green
    
    try {
        # Restaurar configuraciones de rendimiento
        if ($script:originalPrioritySeparation) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value $script:originalPrioritySeparation.Win32PrioritySeparation -ErrorAction SilentlyContinue
        }
        
        # Restaurar configuraciones de memoria
        if ($script:originalLargeSystemCache) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value $script:originalLargeSystemCache.LargeSystemCache -ErrorAction SilentlyContinue
        }
        
        if ($script:originalDisablePagingExecutive) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value $script:originalDisablePagingExecutive.DisablePagingExecutive -ErrorAction SilentlyContinue
        }
        
        Write-Host "[REG] Configuraciones de registro restauradas" -ForegroundColor Gray
        
    } catch {
        Write-Host "[WARN] Error restaurando configuraciones de registro: $_" -ForegroundColor Yellow
    }
}

# ===============================
#  FUNCIONES DE OPTIMIZACION
# ===============================
function Get-GPUVendor {
    try {
        $gpu = Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.Name -notlike "*Basic*" -and $_.Name -notlike "*Generic*" } | Select-Object -First 1
        if ($gpu.Name -like "*NVIDIA*" -or $gpu.Name -like "*GeForce*") {
            return "NVIDIA"
        } elseif ($gpu.Name -like "*AMD*" -or $gpu.Name -like "*Radeon*") {
            return "AMD"
        } elseif ($gpu.Name -like "*Intel*") {
            return "Intel"
        } else {
            return "Unknown"
        }
    } catch {
        return "Unknown"
    }
}

function Set-AdvancedPerformanceOptimizations {
    Write-Host "[REG] Aplicando optimizaciones avanzadas de rendimiento..." -ForegroundColor Green
    
    # Crear backup antes de modificar
    Backup-RegistryGaming
    
    try {
        # Optimizar separación de prioridades para gaming
        $perfKey = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
        if (Test-Path $perfKey) {
            Set-ItemProperty -Path $perfKey -Name "Win32PrioritySeparation" -Value 0x26 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Separación de prioridades optimizada para gaming" -ForegroundColor Gray
        }
        
        # Optimizar gestión de memoria
        $memKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $memKey) {
            Set-ItemProperty -Path $memKey -Name "LargeSystemCache" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $memKey -Name "DisablePagingExecutive" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Gestión de memoria optimizada" -ForegroundColor Gray
        }
        
        # Optimizar sistema de archivos
        $fsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
        if (-not (Test-Path $fsKey)) {
            New-Item -Path $fsKey -Force | Out-Null
        }
        Set-ItemProperty -Path $fsKey -Name "NtfsDisableLastAccessUpdate" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $fsKey -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Write-Host "[REG] Sistema de archivos optimizado" -ForegroundColor Gray
        
        # Optimizar red para gaming
        $tcpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        if (Test-Path $tcpKey) {
            Set-ItemProperty -Path $tcpKey -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $tcpKey -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $tcpKey -Name "TcpDelAckTicks" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Red optimizada para gaming" -ForegroundColor Gray
        }
        
        # Optimizar controladores de red
        $netKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        if (Test-Path $netKey) {
            Get-ChildItem -Path $netKey | ForEach-Object {
                $interfacePath = $_.PSPath
                Set-ItemProperty -Path $interfacePath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $interfacePath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            }
            Write-Host "[REG] Interfaces de red optimizadas" -ForegroundColor Gray
        }
        
        # Optimizar GPU según el fabricante
        $gpuVendor = Get-GPUVendor
        Write-Host "[REG] GPU detectada: $gpuVendor" -ForegroundColor Cyan
        
        if ($gpuVendor -eq "NVIDIA") {
            # Optimizaciones específicas para NVIDIA
            $nvidiaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
            if (-not (Test-Path $nvidiaKey)) {
                New-Item -Path $nvidiaKey -Force | Out-Null
            }
            Set-ItemProperty -Path $nvidiaKey -Name "HwSchMode" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $nvidiaKey -Name "TdrLevel" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Optimizaciones NVIDIA aplicadas" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[WARN] Error aplicando optimizaciones de rendimiento: $_" -ForegroundColor Yellow
    }
}

function Optimize-GraphicsAndMultimedia {
    Write-Host "[REG] Optimizando gráficos y multimedia..." -ForegroundColor Green
    
    try {
        # Optimizar DirectX
        $dxKey = "HKLM:\SOFTWARE\Microsoft\DirectX"
        if (-not (Test-Path $dxKey)) {
            New-Item -Path $dxKey -Force | Out-Null
        }
        
        # Optimizar multimedia
        $mmKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if (Test-Path $mmKey) {
            Set-ItemProperty -Path $mmKey -Name "SystemResponsiveness" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $mmKey -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Perfil multimedia optimizado" -ForegroundColor Gray
        }
        
        # Optimizar tareas de multimedia
        $tasksKey = "$mmKey\Tasks"
        if (Test-Path $tasksKey) {
            Get-ChildItem -Path $tasksKey | ForEach-Object {
                $taskPath = $_.PSPath
                Set-ItemProperty -Path $taskPath -Name "Priority" -Value 6 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $taskPath -Name "Scheduling Category" -Value "High" -Type String -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $taskPath -Name "SFIO Priority" -Value "High" -Type String -ErrorAction SilentlyContinue
            }
            Write-Host "[REG] Tareas multimedia optimizadas" -ForegroundColor Gray
        }
        
        # Optimizar juegos
        $gamesKey = "$mmKey\Tasks\Games"
        if (-not (Test-Path $gamesKey)) {
            New-Item -Path $gamesKey -Force | Out-Null
        }
        Set-ItemProperty -Path $gamesKey -Name "Affinity" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "Background Only" -Value "False" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "Clock Rate" -Value 10000 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "GPU Priority" -Value 8 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "Priority" -Value 6 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "Scheduling Category" -Value "High" -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gamesKey -Name "SFIO Priority" -Value "High" -Type String -ErrorAction SilentlyContinue
        Write-Host "[REG] Configuración de juegos optimizada" -ForegroundColor Gray
        
    } catch {
        Write-Host "[WARN] Error optimizando gráficos y multimedia: $_" -ForegroundColor Yellow
    }
}

function Disable-FSO-HAGS-FocusAssist {
    Write-Host "[REG] Desactivando FSO, HAGS y Focus Assist..." -ForegroundColor Green
    
    try {
        # Desactivar Full Screen Optimization
        $fsoKey = "HKCU:\System\GameConfigStore"
        if (-not (Test-Path $fsoKey)) {
            New-Item -Path $fsoKey -Force | Out-Null
        }
        Set-ItemProperty -Path $fsoKey -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $fsoKey -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $fsoKey -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $fsoKey -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Write-Host "[REG] Full Screen Optimization desactivada" -ForegroundColor Gray
        
        # Desactivar Game Bar
        $gameBarKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
        if (-not (Test-Path $gameBarKey)) {
            New-Item -Path $gameBarKey -Force | Out-Null
        }
        Set-ItemProperty -Path $gameBarKey -Name "AppCaptureEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $gameBarKey -Name "GameDVR_Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Host "[REG] Game Bar desactivada" -ForegroundColor Gray
        
        # Desactivar Hardware Accelerated GPU Scheduling
        $hagsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        if (Test-Path $hagsKey) {
            Set-ItemProperty -Path $hagsKey -Name "HwSchMode" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] HAGS desactivado" -ForegroundColor Gray
        }
        
        # Desactivar Focus Assist
        $focusKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.notifications.quiethours"
        if (Test-Path $focusKey) {
            Set-ItemProperty -Path $focusKey -Name "Value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Focus Assist desactivado" -ForegroundColor Gray
        }
        
        # Desactivar notificaciones durante juegos
        $notifKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
        if (Test-Path $notifKey) {
            Set-ItemProperty -Path $notifKey -Name "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $notifKey -Name "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Notificaciones durante juegos desactivadas" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[WARN] Error desactivando FSO/HAGS/Focus Assist: $_" -ForegroundColor Yellow
    }
}

function Restore-AdvancedPerformanceOptimizations {
    Write-Host "[REG] Restaurando optimizaciones avanzadas..." -ForegroundColor Green
    
    # Restaurar configuraciones de registro
    Restore-RegistryGaming
    
    try {
        # Restaurar configuraciones de red
        $tcpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        if (Test-Path $tcpKey) {
            Remove-ItemProperty -Path $tcpKey -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $tcpKey -Name "TCPNoDelay" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $tcpKey -Name "TcpDelAckTicks" -ErrorAction SilentlyContinue
            Write-Host "[REG] Configuraciones de red restauradas" -ForegroundColor Gray
        }
        
        # Restaurar configuraciones de multimedia
        $mmKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if (Test-Path $mmKey) {
            Set-ItemProperty -Path $mmKey -Name "SystemResponsiveness" -Value 20 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $mmKey -Name "NetworkThrottlingIndex" -Value 10 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "[REG] Configuraciones multimedia restauradas" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[WARN] Error restaurando optimizaciones avanzadas: $_" -ForegroundColor Yellow
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE6] Iniciando optimizaciones de registro y gráficos..." -ForegroundColor Green

# Aplicar optimizaciones avanzadas de rendimiento
Set-AdvancedPerformanceOptimizations

# Optimizar gráficos y multimedia
Optimize-GraphicsAndMultimedia

# Desactivar FSO, HAGS y Focus Assist
Disable-FSO-HAGS-FocusAssist

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 6: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE6] Optimizaciones de registro y gráficos completadas" -ForegroundColor Green

# Guardar información para restauración posterior
$registryInfo = @{
    RegistryBackup = $script:registryBackup
    OriginalValues = @{
        PrioritySeparation = $script:originalPrioritySeparation
        LargeSystemCache = $script:originalLargeSystemCache
        DisablePagingExecutive = $script:originalDisablePagingExecutive
    }
    Timestamp = Get-Date
}

# Crear archivo de configuración temporal
$configPath = Join-Path $env:TEMP "OptimizadorRegistro.json"
$registryInfo | ConvertTo-Json -Depth 3 | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "[INFO] Configuración guardada en: $configPath" -ForegroundColor Gray
