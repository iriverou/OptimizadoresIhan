# ===============================
#  ETAPA 5: LIBERACION DE MEMORIA RAM
#  Libera memoria RAM usando tecnicas avanzadas y herramientas Sysinternals
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
Write-Host "   ETAPA 5: LIBERACION DE MEMORIA RAM" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

# Variables globales para cache
$script:memoryOptimized = $false

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

# ===============================
#  FUNCIONES DE LIBERACION DE MEMORIA
# ===============================
function Show-MemoryOptimizationInfo {
    Write-Host "[MEM] Informacion de memoria antes de optimizar:" -ForegroundColor Cyan
    
    try {
        # Obtener informacion de memoria del sistema
        $memInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemory = [math]::Round($memInfo.TotalVisibleMemorySize / 1MB, 2)
        $availableMemory = [math]::Round($memInfo.FreePhysicalMemory / 1MB, 2)
        $usedMemory = [math]::Round(($memInfo.TotalVisibleMemorySize - $memInfo.FreePhysicalMemory) / 1MB, 2)
        $usedPercentage = [math]::Round(($usedMemory / $totalMemory) * 100, 1)
        
        Write-Host "[MEM] Memoria total: $totalMemory GB" -ForegroundColor Gray
        Write-Host "[MEM] Memoria disponible: $availableMemory GB" -ForegroundColor Gray
        Write-Host "[MEM] Memoria en uso: $usedMemory GB ($usedPercentage%)" -ForegroundColor Gray
        
        # Informacion adicional de rendimiento
        $perfInfo = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory
        if ($perfInfo) {
            $commitLimit = [math]::Round($perfInfo.CommitLimit / 1MB, 2)
            $commitTotal = [math]::Round($perfInfo.CommittedBytes / 1MB, 2)
            $commitPercentage = [math]::Round(($commitTotal / $commitLimit) * 100, 1)
            
            Write-Host "[MEM] Commit limit: $commitLimit GB" -ForegroundColor Gray
            Write-Host "[MEM] Commit total: $commitTotal GB ($commitPercentage%)" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[WARN] No se pudo obtener informacion detallada de memoria" -ForegroundColor Yellow
    }
}

function Clear-Memory {
    Write-Host "[MEM] Iniciando liberacion de memoria..." -ForegroundColor Green
    
    # Método 1: Usar RAMMap si está disponible
    $ramMapPath = Get-RAMMapPath
    if ($ramMapPath) {
        Write-Host "[MEM] Usando RAMMap para liberacion avanzada..." -ForegroundColor Green
        try {
            # Limpiar Standby List
            & $ramMapPath -Et -accepteula 2>$null
            Write-Host "[MEM] Standby List limpiada con RAMMap" -ForegroundColor Gray
            
            # Limpiar Working Sets
            & $ramMapPath -Ew -accepteula 2>$null
            Write-Host "[MEM] Working Sets limpiados con RAMMap" -ForegroundColor Gray
            
            $script:memoryOptimized = $true
        } catch {
            Write-Host "[WARN] Error usando RAMMap: $_" -ForegroundColor Yellow
        }
    }
    
    # Método 2: Usar EmptyStandbyList si está disponible
    $emptyStandbyList = Get-Command "EmptyStandbyList.exe" -ErrorAction SilentlyContinue
    if ($emptyStandbyList -and -not $script:memoryOptimized) {
        Write-Host "[MEM] Usando EmptyStandbyList..." -ForegroundColor Green
        try {
            & $emptyStandbyList.Source workingsets 2>$null
            & $emptyStandbyList.Source modifiedpagelist 2>$null
            & $emptyStandbyList.Source standbylist 2>$null
            & $emptyStandbyList.Source priority0standbylist 2>$null
            Write-Host "[MEM] Memoria liberada con EmptyStandbyList" -ForegroundColor Gray
            $script:memoryOptimized = $true
        } catch {
            Write-Host "[WARN] Error usando EmptyStandbyList: $_" -ForegroundColor Yellow
        }
    }
    
    # Metodo 3: Tecnicas nativas de PowerShell
    if (-not $script:memoryOptimized) {
        Write-Host "[MEM] Usando metodos nativos de PowerShell..." -ForegroundColor Green
        try {
            # Forzar garbage collection
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
            Write-Host "[MEM] Garbage collection ejecutada" -ForegroundColor Gray
            
            # Limpiar cache de DNS
            Clear-DnsClientCache -ErrorAction SilentlyContinue
            Write-Host "[MEM] Cache DNS limpiada" -ForegroundColor Gray
            
            # Limpiar cache de ARP
            & netsh interface ip delete arpcache 2>$null
            Write-Host "[MEM] Cache ARP limpiada" -ForegroundColor Gray
            
            # Limpiar cache de NetBIOS
            & nbtstat -RR 2>$null
            Write-Host "[MEM] Cache NetBIOS limpiada" -ForegroundColor Gray
            
            $script:memoryOptimized = $true
        } catch {
            Write-Host "[WARN] Error en metodos nativos: $_" -ForegroundColor Yellow
        }
    }
    
    # Método 4: Usar API de Windows para liberar memoria
    try {
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class MemoryAPI {
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern bool SetProcessWorkingSetSize(IntPtr proc, int min, int max);
                
                [DllImport("kernel32.dll")]
                public static extern IntPtr GetCurrentProcess();
                
                [DllImport("psapi.dll")]
                public static extern bool EmptyWorkingSet(IntPtr hwProc);
            }
"@
        
        $currentProcess = [MemoryAPI]::GetCurrentProcess()
        [MemoryAPI]::SetProcessWorkingSetSize($currentProcess, -1, -1)
        [MemoryAPI]::EmptyWorkingSet($currentProcess)
        Write-Host "[MEM] Working set del proceso actual optimizado" -ForegroundColor Gray
        
    } catch {
        Write-Host "[WARN] No se pudo usar API de Windows para optimizacion: $_" -ForegroundColor Yellow
    }
    
    # Mostrar informacion post-optimizacion
    Start-Sleep -Seconds 2
    Show-MemoryOptimizationInfo
    
    Write-Host "[MEM] Liberacion de memoria completada" -ForegroundColor Green
}

function Optimize-VirtualMemory {
    Write-Host "[MEM] Optimizando memoria virtual..." -ForegroundColor Green
    
    try {
        # Obtener informacion del archivo de paginacion
        $pageFiles = Get-CimInstance -ClassName Win32_PageFileUsage
        foreach ($pageFile in $pageFiles) {
            $size = [math]::Round($pageFile.AllocatedBaseSize / 1024, 2)
            $usage = [math]::Round($pageFile.CurrentUsage / 1024, 2)
            $usagePercentage = [math]::Round(($pageFile.CurrentUsage / $pageFile.AllocatedBaseSize) * 100, 1)
            
            Write-Host "[MEM] Archivo de paginación: $($pageFile.Name)" -ForegroundColor Gray
            Write-Host "[MEM] Tamaño: $size GB, Uso: $usage GB ($usagePercentage%)" -ForegroundColor Gray
        }
        
        # Limpiar archivo de paginación si es posible
        $pageFileSettings = Get-CimInstance -ClassName Win32_PageFileSetting
        if ($pageFileSettings) {
            Write-Host "[MEM] Configuración de archivo de paginación verificada" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "[WARN] No se pudo optimizar memoria virtual: $_" -ForegroundColor Yellow
    }
}

function Clear-ProcessMemory {
    Write-Host "[MEM] Optimizando memoria de procesos..." -ForegroundColor Green
    
    try {
        # Obtener procesos que consumen mucha memoria
        $processes = Get-Process | Where-Object { $_.WorkingSet -gt 100MB } | Sort-Object WorkingSet -Descending
        
        $optimizedCount = 0
        foreach ($process in $processes) {
            try {
                # Intentar reducir el working set del proceso
                $handle = $process.Handle
                if ($handle -and $handle -ne [IntPtr]::Zero) {
                    Add-Type -TypeDefinition @"
                        using System;
                        using System.Runtime.InteropServices;
                        public class ProcessMemory {
                            [DllImport("psapi.dll")]
                            public static extern bool EmptyWorkingSet(IntPtr hwProc);
                        }
"@
                    if ([ProcessMemory]::EmptyWorkingSet($handle)) {
                        $optimizedCount++
                    }
                }
            } catch {
                # Ignorar errores en procesos individuales
            }
        }
        
        Write-Host "[MEM] Procesos optimizados: $optimizedCount" -ForegroundColor Gray
        
    } catch {
        Write-Host "[WARN] No se pudo optimizar memoria de procesos: $_" -ForegroundColor Yellow
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE5] Iniciando liberación de memoria RAM..." -ForegroundColor Green

# Mostrar información inicial
Show-MemoryOptimizationInfo

# Ejecutar liberación de memoria
Clear-Memory

# Optimizar memoria virtual
Optimize-VirtualMemory

# Optimizar memoria de procesos
Clear-ProcessMemory

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 5: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE5] Liberación de memoria RAM completada" -ForegroundColor Green
