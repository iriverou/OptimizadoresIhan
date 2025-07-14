# ===============================
#  ETAPA 1: VERIFICACION DE HERRAMIENTAS Y CONFIGURACION
#  Verifica herramientas Sysinternals y configuracion del sistema
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
Write-Host "   ETAPA 1: VERIFICACION DE HERRAMIENTAS" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

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

function Show-AvailableTools {
    $tools = @()
    
    # Verificar CoreInfo
    $coreinfo = Get-CoreInfoPath
    if ($coreinfo) {
        $tools += "[TOOL] CoreInfo encontrado: $coreinfo"
    } else {
        $tools += "[TOOL] CoreInfo no encontrado (opcional)"
    }
    
    # Verificar RAMMap
    $rammap = Get-RAMMapPath
    if ($rammap) {
        $tools += "[TOOL] RAMMap encontrado: $rammap"
    } else {
        $tools += "[TOOL] RAMMap no encontrado (opcional)"
    }
    
    # Verificar EmptyStandbyList
    $emptyStandbyList = Get-Command "EmptyStandbyList.exe" -ErrorAction SilentlyContinue
    if ($emptyStandbyList) {
        $tools += "[TOOL] EmptyStandbyList encontrado: $($emptyStandbyList.Source)"
    } else {
        $tools += "[TOOL] EmptyStandbyList no encontrado (opcional)"
    }
    
    # Mostrar herramientas disponibles
    Write-Host "[TOOLS] Herramientas Sysinternals disponibles:" -ForegroundColor Cyan
    foreach ($tool in $tools) {
        Write-Host $tool -ForegroundColor Gray
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE1] Iniciando verificacion de herramientas..." -ForegroundColor Green

# Mostrar herramientas disponibles
Show-AvailableTools

# Verificar version de PowerShell
Write-Host "[STAGE1] Verificando PowerShell..." -ForegroundColor Green
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "[ERROR] Este script requiere PowerShell 5.1 o superior." -ForegroundColor Red
    Write-Host "Version detectada: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[OK] PowerShell $($PSVersionTable.PSVersion) - Compatible" -ForegroundColor Green
}

# Verificar permisos de administrador
Write-Host "[STAGE1] Verificando permisos de administrador..." -ForegroundColor Green
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[OK] Permisos de administrador verificados" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Se requieren permisos de administrador" -ForegroundColor Red
    exit 1
}

# Verificar parametros
Write-Host "[STAGE1] Configuracion actual:" -ForegroundColor Green
Write-Host "  - Modo Debug: $($DebugMode.ToString())" -ForegroundColor Gray
Write-Host "  - Modo Affinity: $AffinityMode" -ForegroundColor Gray

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 1: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE1] Verificacion de herramientas completada" -ForegroundColor Green
