# ===============================
#  ETAPA 2: CONFIGURACION DE ENERGIA
#  Configura el plan de energía para máximo rendimiento
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
Write-Host "   ETAPA 2: CONFIGURACION DE ENERGIA" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

# Variables globales para planes de energía
$script:originalPlan = $null
$script:highPerfPlan = $null

# ===============================
#  FUNCIONES DE ENERGIA
# ===============================
function Get-CurrentPowerPlan {
    try {
        # Usar WMI para obtener el plan activo
        $activePlan = Get-WmiObject -Class win32_powerplan -Namespace "root\cimv2\power" -Filter "IsActive=TRUE"
        if ($activePlan) {
            return $activePlan.InstanceID.Split('\')[1]
        }
        
        # Fallback usando powercfg
        $currentPlan = & powercfg /getactivescheme 2>$null
        if ($currentPlan -and $currentPlan -match '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b') {
            return $matches[0]
        }
        
        return $null
    } catch {
        Write-Host "[WARN] Error obteniendo plan actual: $_" -ForegroundColor Yellow
        return $null
    }
}

function Set-PowerPlanByGuid($guid) {
    try {
        $result = & powercfg /setactive $guid 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $true
        } else {
            Write-Host "[WARN] Error estableciendo plan: $result" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "[WARN] Error en Set-PowerPlanByGuid: $_" -ForegroundColor Yellow
        return $false
    }
}

function Get-HighPerformancePlanGuid {
    try {
        # Obtener todos los planes de energía disponibles
        $powerPlans = & powercfg /list 2>$null
        
        # Buscar variaciones del plan de alto rendimiento
        $highPerfNames = @('High performance', 'Alto rendimiento', 'Rendimiento alto', 'Ultimate Performance', 'Máximo rendimiento')
        
        foreach ($line in $powerPlans) {
            if ($line -match '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b') {
                $guid = $matches[0]
                foreach ($name in $highPerfNames) {
                    if ($line -match $name) {
                        return $guid
                    }
                }
            }
        }
        
        # Si no se encuentra, intentar crear uno usando el GUID estándar
        $standardGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        & powercfg /setactive $standardGuid 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $standardGuid
        }
        
        return $null
    } catch {
        Write-Host "[WARN] Error obteniendo plan de alto rendimiento: $_" -ForegroundColor Yellow
        return $null
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE2] Iniciando configuración de energía..." -ForegroundColor Green

# Obtener plan actual
$script:originalPlan = Get-CurrentPowerPlan
if ($script:originalPlan) {
    Write-Host "[POWER] Plan actual: $script:originalPlan" -ForegroundColor Cyan
} else {
    Write-Host "[WARN] No se pudo obtener el plan actual" -ForegroundColor Yellow
}

# Obtener plan de alto rendimiento
$script:highPerfPlan = Get-HighPerformancePlanGuid
if ($script:highPerfPlan) {
    Write-Host "[POWER] Plan de alto rendimiento encontrado: $script:highPerfPlan" -ForegroundColor Cyan
    
    # Activar plan de alto rendimiento
    if (Set-PowerPlanByGuid $script:highPerfPlan) {
        Write-Host "[POWER] Plan de alto rendimiento activado" -ForegroundColor Green
        
        # Configurar opciones adicionales del plan de energía
        Write-Host "[POWER] Configurando opciones avanzadas..." -ForegroundColor Green
        
        # Desactivar USB selective suspend
        & powercfg /setacvalueindex $script:highPerfPlan 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        & powercfg /setdcvalueindex $script:highPerfPlan 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        
        # Configurar modo de procesador a máximo rendimiento
        & powercfg /setacvalueindex $script:highPerfPlan 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>$null
        & powercfg /setdcvalueindex $script:highPerfPlan 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>$null
        
        # Desactivar hibernación del disco duro
        & powercfg /setacvalueindex $script:highPerfPlan 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0 2>$null
        & powercfg /setdcvalueindex $script:highPerfPlan 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0 2>$null
        
        # Aplicar cambios
        & powercfg /setactive $script:highPerfPlan 2>$null
        
        Write-Host "[POWER] Configuración avanzada aplicada" -ForegroundColor Green
    } else {
        Write-Host "[WARN] No se pudo activar el plan de alto rendimiento" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Plan de alto rendimiento no encontrado" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 2: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE2] Configuración de energía completada" -ForegroundColor Green

# Guardar información para restauración posterior
$planInfo = @{
    OriginalPlan = $script:originalPlan
    HighPerfPlan = $script:highPerfPlan
    Timestamp = Get-Date
}

# Crear archivo de configuración temporal
$configPath = Join-Path $env:TEMP "OptimizadorEnergia.json"
$planInfo | ConvertTo-Json | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "[INFO] Configuración guardada en: $configPath" -ForegroundColor Gray
