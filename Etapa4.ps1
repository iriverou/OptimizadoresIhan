# ===============================
#  ETAPA 4: LIMPIEZA DE ARCHIVOS Y CACHE
#  Limpia archivos temporales, cache y prefetch
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
Write-Host "   ETAPA 4: LIMPIEZA DE ARCHIVOS Y CACHE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Yellow

# ===============================
#  FUNCIONES DE LIMPIEZA
# ===============================
function Clear-TempFiles {
    Write-Host "[CLEAN] Limpiando archivos temporales..." -ForegroundColor Green
    
    $tempPaths = @(
        $env:TEMP,
        $env:TMP,
        "$env:WINDIR\Temp",
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\AppData\Local\Temp"
    )
    
    $totalCleaned = 0
    $totalSize = 0
    
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    try {
                        if ($file.PSIsContainer) {
                            Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        } else {
                            $totalSize += $file.Length
                            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                        }
                        $totalCleaned++
                    } catch {
                        # Ignorar errores de archivos en uso
                    }
                }
                Write-Host "[CLEAN] Limpiado: $path" -ForegroundColor Gray
            } catch {
                Write-Host "[WARN] No se pudo limpiar: $path" -ForegroundColor Yellow
            }
        }
    }
    
    $sizeInMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "[CLEAN] Archivos temporales eliminados: $totalCleaned ($sizeInMB MB)" -ForegroundColor Green
}

function Clear-ExplorerCache {
    Write-Host "[CLEAN] Limpiando cache del explorador..." -ForegroundColor Green
    
    $cachePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache*.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*.db",
        "$env:LOCALAPPDATA\IconCache.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*",
        "$env:APPDATA\Microsoft\Windows\Recent\*",
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*",
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
    )
    
    $totalCleaned = 0
    $totalSize = 0
    
    foreach ($pattern in $cachePaths) {
        try {
            $files = Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    if (-not $file.PSIsContainer) {
                        $totalSize += $file.Length
                    }
                    Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    $totalCleaned++
                } catch {
                    # Ignorar errores de archivos en uso
                }
            }
        } catch {
            # Ignorar errores de acceso
        }
    }
    
    $sizeInMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "[CLEAN] Cache del explorador eliminado: $totalCleaned archivos ($sizeInMB MB)" -ForegroundColor Green
}

function Clear-Prefetch {
    Write-Host "[CLEAN] Limpiando prefetch..." -ForegroundColor Green
    
    $prefetchPath = "$env:WINDIR\Prefetch"
    $totalCleaned = 0
    $totalSize = 0
    
    if (Test-Path $prefetchPath) {
        try {
            $files = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $totalSize += $file.Length
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    $totalCleaned++
                } catch {
                    # Ignorar errores de archivos en uso
                }
            }
            
            $sizeInMB = [math]::Round($totalSize / 1MB, 2)
            Write-Host "[CLEAN] Prefetch eliminado: $totalCleaned archivos ($sizeInMB MB)" -ForegroundColor Green
        } catch {
            Write-Host "[WARN] No se pudo limpiar prefetch" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] Directorio prefetch no encontrado" -ForegroundColor Yellow
    }
}

function Clear-AdditionalCaches {
    Write-Host "[CLEAN] Limpiando caches adicionales..." -ForegroundColor Green
    
    $additionalPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\Caches\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\History\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\WER\*",
        "$env:LOCALAPPDATA\CrashDumps\*",
        "$env:WINDIR\Logs\*",
        "$env:WINDIR\Panther\*",
        "$env:WINDIR\system32\LogFiles\*",
        "$env:WINDIR\system32\WDI\LogFiles\*"
    )
    
    $totalCleaned = 0
    $totalSize = 0
    
    foreach ($pattern in $additionalPaths) {
        try {
            $files = Get-ChildItem -Path $pattern -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    if (-not $file.PSIsContainer) {
                        $totalSize += $file.Length
                    }
                    Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    $totalCleaned++
                } catch {
                    # Ignorar errores de archivos en uso
                }
            }
        } catch {
            # Ignorar errores de acceso
        }
    }
    
    $sizeInMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "[CLEAN] Caches adicionales eliminados: $totalCleaned elementos ($sizeInMB MB)" -ForegroundColor Green
}

function Clear-SystemCaches {
    Write-Host "[CLEAN] Limpiando caches del sistema..." -ForegroundColor Green
    
    # Limpiar cache de Windows Update
    try {
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "cryptSvc" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "bits" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
        
        $updatePaths = @(
            "$env:WINDIR\SoftwareDistribution\Download\*",
            "$env:WINDIR\System32\catroot2\*"
        )
        
        $totalCleaned = 0
        $totalSize = 0
        
        foreach ($pattern in $updatePaths) {
            try {
                $files = Get-ChildItem -Path $pattern -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    try {
                        if (-not $file.PSIsContainer) {
                            $totalSize += $file.Length
                        }
                        Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        $totalCleaned++
                    } catch {
                        # Ignorar errores de archivos en uso
                    }
                }
            } catch {
                # Ignorar errores de acceso
            }
        }
        
        $sizeInMB = [math]::Round($totalSize / 1MB, 2)
        Write-Host "[CLEAN] Cache del sistema eliminado: $totalCleaned elementos ($sizeInMB MB)" -ForegroundColor Green
        
        # Reiniciar servicios
        Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        Start-Service -Name "cryptSvc" -ErrorAction SilentlyContinue
        Start-Service -Name "bits" -ErrorAction SilentlyContinue
        Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "[WARN] No se pudo limpiar completamente el cache del sistema" -ForegroundColor Yellow
    }
}

# ===============================
#  EJECUCION PRINCIPAL
# ===============================
Write-Host "[STAGE4] Iniciando limpieza de archivos y cache..." -ForegroundColor Green

# Limpiar archivos temporales
Clear-TempFiles

# Limpiar cache del explorador
Clear-ExplorerCache

# Limpiar prefetch
Clear-Prefetch

# Limpiar caches adicionales
Clear-AdditionalCaches

# Limpiar caches del sistema
Clear-SystemCaches

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   ETAPA 4: COMPLETADA EXITOSAMENTE" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[STAGE4] Limpieza de archivos y cache completada" -ForegroundColor Green
