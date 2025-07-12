# ===============================
#  MAIN - COORDINADOR DE ETAPAS DEL OPTIMIZADOR
#  Ejecuta todas las etapas en orden o etapas específicas
# ===============================

param(
    [switch]$DebugMode,
    [ValidateSet('auto','estandar')][string]$AffinityMode = 'auto',
    [ValidateSet('all','1','2','3','4','5','6')][string]$RunStage = 'all',
    [switch]$SkipGameMonitoring,
    [switch]$NoRestore
)

# ===============================
#  VERIFICACION DE PERMISOS
# ===============================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] El coordinador requiere permisos de administrador" -ForegroundColor Red
    Write-Host "[INFO] Reiniciando como administrador..." -ForegroundColor Yellow
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($DebugMode) { $argList += " -DebugMode" }
    if ($AffinityMode -ne 'auto') { $argList += " -AffinityMode $AffinityMode" }
    if ($RunStage -ne 'all') { $argList += " -RunStage $RunStage" }
    if ($SkipGameMonitoring) { $argList += " -SkipGameMonitoring" }
    if ($NoRestore) { $argList += " -NoRestore" }
    Start-Process -FilePath "powershell" -ArgumentList $argList -Verb RunAs
    exit
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   COORDINADOR DE ETAPAS - OPTIMIZADOR CS2" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "[MAIN] Modo Debug: $($DebugMode.ToString())" -ForegroundColor Gray
Write-Host "[MAIN] Modo Affinity: $AffinityMode" -ForegroundColor Gray
Write-Host "[MAIN] Ejecutar: $RunStage" -ForegroundColor Gray
Write-Host "[MAIN] Monitoreo de juego: $(-not $SkipGameMonitoring)" -ForegroundColor Gray
Write-Host "[MAIN] Restaurar al final: $(-not $NoRestore)" -ForegroundColor Gray
Write-Host "=============================================" -ForegroundColor Cyan

# ===============================
#  FUNCIONES DE UTILIDAD
# ===============================
function Get-ScriptDirectory {
    if ($PSScriptRoot) {
        return $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        return Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        return Get-Location
    }
}

function Test-EtapaFile {
    param([string]$etapaNumber)
    $scriptDir = Get-ScriptDirectory
    $etapaPath = Join-Path $scriptDir "Etapa$etapaNumber.ps1"
    return Test-Path $etapaPath
}

function Invoke-Etapa {
    param(
        [string]$etapaNumber,
        [string]$description
    )
    
    $scriptDir = Get-ScriptDirectory
    $etapaPath = Join-Path $scriptDir "Etapa$etapaNumber.ps1"
    
    if (-not (Test-Path $etapaPath)) {
        Write-Host "[ERROR] Etapa $etapaNumber no encontrada: $etapaPath" -ForegroundColor Red
        return $false
    }
    
    Write-Host ""
    Write-Host "[MAIN] Ejecutando Etapa $etapaNumber : $description" -ForegroundColor Yellow
    Write-Host "[MAIN] Archivo: $etapaPath" -ForegroundColor Gray
    
    try {
        $arguments = @()
        if ($DebugMode) { $arguments += "-DebugMode" }
        if ($AffinityMode -ne 'auto') { $arguments += "-AffinityMode", $AffinityMode }
        
        if ($arguments.Count -gt 0) {
            & $etapaPath @arguments
        } else {
            & $etapaPath
        }
        
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
            Write-Host "[MAIN] Etapa $etapaNumber completada exitosamente" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[MAIN] Etapa $etapaNumber falló con código $LASTEXITCODE" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "[MAIN] Error ejecutando Etapa $etapaNumber : $_" -ForegroundColor Red
        return $false
    }
}

function Wait-ForGameProcess {
    param(
        [string]$processName,
        [string]$displayName
    )
    
    if ($SkipGameMonitoring) {
        Write-Host "[MAIN] Monitoreo de juego desactivado" -ForegroundColor Yellow
        return
    }
    
    Write-Host "[MAIN] Esperando a que $displayName inicie..." -ForegroundColor Cyan
    Write-Host "[MAIN] Ejecuta el juego manualmente desde Steam" -ForegroundColor Gray
    
    while ($true) {
        $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "[MAIN] $displayName detectado (PID: $($proc.Id))" -ForegroundColor Green
            Write-Host "[MAIN] Aplicando optimizaciones al proceso..." -ForegroundColor Green
            
            try {
                # Aplicar prioridad alta
                $proc.PriorityClass = 'High'
                Write-Host "[MAIN] Prioridad alta aplicada" -ForegroundColor Gray
                
                # Aplicar afinidad de CPU (todos los núcleos excepto el 0)
                $cpuCount = [Environment]::ProcessorCount
                if ($cpuCount -gt 1) {
                    $affinity = [int]([math]::Pow(2, $cpuCount) - 2)
                    $proc.ProcessorAffinity = $affinity
                    Write-Host "[MAIN] Afinidad de CPU aplicada: $affinity" -ForegroundColor Gray
                }
                
            } catch {
                Write-Host "[WARN] No se pudo aplicar todas las optimizaciones: $_" -ForegroundColor Yellow
            }
            
            Write-Host "[MAIN] Esperando a que $displayName finalice..." -ForegroundColor Cyan
            $proc.WaitForExit()
            Write-Host "[MAIN] $displayName cerrado" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 2
    }
}

function Restore-SystemConfiguration {
    if ($NoRestore) {
        Write-Host "[MAIN] Restauración desactivada" -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    Write-Host "[MAIN] Iniciando restauración del sistema..." -ForegroundColor Yellow
    
    try {
        # Restaurar plan de energía
        $energyConfig = Join-Path $env:TEMP "OptimizadorEnergia.json"
        if (Test-Path $energyConfig) {
            $config = Get-Content $energyConfig | ConvertFrom-Json
            if ($config.OriginalPlan -and $config.HighPerfPlan -and $config.OriginalPlan -ne $config.HighPerfPlan) {
                & powercfg /setactive $config.OriginalPlan 2>$null
                Write-Host "[MAIN] Plan de energía restaurado" -ForegroundColor Green
            }
        }
        
        # Restaurar servicios
        $serviceConfig = Join-Path $env:TEMP "OptimizadorServicios.json"
        if (Test-Path $serviceConfig) {
            $config = Get-Content $serviceConfig | ConvertFrom-Json
            if ($config.StoppedServices) {
                $restoredCount = 0
                foreach ($serviceName in $config.StoppedServices) {
                    try {
                        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                        if ($service -and $service.Status -eq 'Stopped') {
                            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                            $restoredCount++
                        }
                    } catch {
                        # Ignorar errores
                    }
                }
                Write-Host "[MAIN] Servicios restaurados: $restoredCount" -ForegroundColor Green
            }
        }
        
        # Restaurar configuraciones de registro
        $registryConfig = Join-Path $env:TEMP "OptimizadorRegistro.json"
        if (Test-Path $registryConfig) {
            $config = Get-Content $registryConfig | ConvertFrom-Json
            if ($config.OriginalValues) {
                # Restaurar separación de prioridades
                if ($config.OriginalValues.PrioritySeparation) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value $config.OriginalValues.PrioritySeparation.Win32PrioritySeparation -ErrorAction SilentlyContinue
                }
                
                # Restaurar configuraciones de memoria
                if ($config.OriginalValues.LargeSystemCache) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value $config.OriginalValues.LargeSystemCache.LargeSystemCache -ErrorAction SilentlyContinue
                }
                
                if ($config.OriginalValues.DisablePagingExecutive) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value $config.OriginalValues.DisablePagingExecutive.DisablePagingExecutive -ErrorAction SilentlyContinue
                }
                
                Write-Host "[MAIN] Configuraciones de registro restauradas" -ForegroundColor Green
            }
        }
        
        # Limpiar archivos temporales de configuración
        Remove-Item -Path $energyConfig -ErrorAction SilentlyContinue
        Remove-Item -Path $serviceConfig -ErrorAction SilentlyContinue
        Remove-Item -Path $registryConfig -ErrorAction SilentlyContinue
        
        Write-Host "[MAIN] Restauración completada" -ForegroundColor Green
        
    } catch {
        Write-Host "[WARN] Error durante la restauración: $_" -ForegroundColor Yellow
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
$startTime = Get-Date
$successfulStages = @()
$failedStages = @()

# Definir etapas disponibles
$etapas = @{
    '1' = 'Verificación de herramientas y configuración'
    '2' = 'Configuración de energía'
    '3' = 'Optimización de procesos y servicios'
    '4' = 'Limpieza de archivos y cache'
    '5' = 'Liberación de memoria RAM'
    '6' = 'Optimizaciones de registro y gráficos'
}

# Determinar qué etapas ejecutar
$etapasToRun = @()
if ($RunStage -eq 'all') {
    $etapasToRun = @('1', '2', '3', '4', '5', '6')
} else {
    $etapasToRun = @($RunStage)
}

# Verificar que todas las etapas existen
$missingStages = @()
foreach ($etapa in $etapasToRun) {
    if (-not (Test-EtapaFile $etapa)) {
        $missingStages += $etapa
    }
}

if ($missingStages.Count -gt 0) {
    Write-Host "[ERROR] Etapas faltantes: $($missingStages -join ', ')" -ForegroundColor Red
    exit 1
}

# Ejecutar etapas
Write-Host ""
Write-Host "[MAIN] Ejecutando $($etapasToRun.Count) etapa(s)..." -ForegroundColor Green

foreach ($etapa in $etapasToRun) {
    $description = $etapas[$etapa]
    $success = Invoke-Etapa -etapaNumber $etapa -description $description
    
    if ($success) {
        $successfulStages += $etapa
    } else {
        $failedStages += $etapa
        
        # Preguntar si continuar en caso de fallo
        Write-Host ""
        Write-Host "[MAIN] ¿Continuar con las siguientes etapas? (S/N)" -ForegroundColor Yellow
        $response = Read-Host
        if ($response -notmatch '^[Ss]') {
            Write-Host "[MAIN] Ejecución cancelada por el usuario" -ForegroundColor Yellow
            break
        }
    }
}

# Mostrar sistema optimizado
if ($successfulStages.Count -gt 0) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "   SISTEMA OPTIMIZADO - LISTO PARA GAMING" -ForegroundColor White
    Write-Host "=============================================" -ForegroundColor Green
    
    # Monitorear proceso de juego
    if ($RunStage -eq 'all' -or $RunStage -eq '6') {
        if ($DebugMode) {
            Wait-ForGameProcess -processName 'hl' -displayName 'CS 1.6 (hl.exe)'
        } else {
            Wait-ForGameProcess -processName 'peak' -displayName 'Peak (peak.exe)'
        }
    }
    
    # Restaurar sistema
    Restore-SystemConfiguration
}

# Mostrar resumen final
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   RESUMEN DE EJECUCION" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "[MAIN] Duración total: $($duration.TotalSeconds.ToString('F1')) segundos" -ForegroundColor Gray
Write-Host "[MAIN] Etapas exitosas: $($successfulStages.Count)" -ForegroundColor Green
Write-Host "[MAIN] Etapas fallidas: $($failedStages.Count)" -ForegroundColor Red

if ($successfulStages.Count -gt 0) {
    Write-Host "[MAIN] Etapas completadas: $($successfulStages -join ', ')" -ForegroundColor Green
}

if ($failedStages.Count -gt 0) {
    Write-Host "[MAIN] Etapas fallidas: $($failedStages -join ', ')" -ForegroundColor Red
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   OPTIMIZADOR CS2 - FINALIZADO" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[MAIN] Presiona cualquier tecla para cerrar..." -ForegroundColor Gray
Read-Host
