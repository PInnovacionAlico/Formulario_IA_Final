# Script de utilidad para Docker en Windows
# Uso: .\docker-helper.ps1 [comando]

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

function Print-Header {
    Write-Host "================================" -ForegroundColor Green
    Write-Host "  Formulario IA - Docker Helper" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host ""
}

function Print-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Print-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Print-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Check-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Print-Error "Docker no está instalado"
        Write-Host "Visita: https://www.docker.com/get-started"
        exit 1
    }
    Print-Success "Docker encontrado"
}

function Check-Env {
    if (-not (Test-Path .env)) {
        Print-Warning "Archivo .env no encontrado"
        Write-Host "Creando .env desde .env.example..."
        Copy-Item .env.example .env
        Print-Warning "Por favor, edita .env con tus valores reales antes de continuar"
        exit 1
    }
    Print-Success "Archivo .env encontrado"
}

function Build-Image {
    Print-Header
    Write-Host "🔨 Construyendo imagen Docker..."
    docker-compose build
    Print-Success "Imagen construida exitosamente"
}

function Start-App {
    Print-Header
    Check-Docker
    Check-Env
    Write-Host "🚀 Iniciando aplicación..."
    docker-compose up -d
    Print-Success "Aplicación iniciada"
    Write-Host ""
    Write-Host "📍 Accede a: http://localhost:3000" -ForegroundColor Cyan
    Write-Host "📊 Ver logs: .\docker-helper.ps1 logs" -ForegroundColor Cyan
}

function Stop-App {
    Print-Header
    Write-Host "🛑 Deteniendo aplicación..."
    docker-compose down
    Print-Success "Aplicación detenida"
}

function Restart-App {
    Print-Header
    Write-Host "🔄 Reiniciando aplicación..."
    docker-compose restart
    Print-Success "Aplicación reiniciada"
}

function Show-Logs {
    Write-Host "📋 Mostrando logs (Ctrl+C para salir)..."
    docker-compose logs -f
}

function Show-Status {
    Print-Header
    Write-Host "📊 Estado de los contenedores:"
    Write-Host ""
    docker-compose ps
}

function Clean-All {
    Print-Header
    Print-Warning "Esto eliminará todos los contenedores, imágenes y volúmenes"
    $confirmation = Read-Host "¿Estás seguro? (y/N)"
    if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
        docker-compose down -v --rmi all
        Print-Success "Limpieza completada"
    } else {
        Write-Host "Cancelado"
    }
}

function Open-Shell {
    Print-Header
    Write-Host "🐚 Abriendo shell en el contenedor..."
    docker-compose exec app sh
}

function Generate-JWT {
    Print-Header
    Write-Host "🔑 Generando JWT Secret..."
    
    # Generar JWT usando .NET crypto
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $jwtSecret = [System.BitConverter]::ToString($bytes).Replace("-", "").ToLower()
    
    Write-Host ""
    Print-Success "JWT Secret generado:"
    Write-Host ""
    Write-Host $jwtSecret -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Copia este valor a tu archivo .env"
}

function Show-Help {
    Print-Header
    Write-Host "Comandos disponibles:"
    Write-Host ""
    Write-Host "  build        - Construir la imagen Docker" -ForegroundColor Cyan
    Write-Host "  start        - Iniciar la aplicación" -ForegroundColor Cyan
    Write-Host "  stop         - Detener la aplicación" -ForegroundColor Cyan
    Write-Host "  restart      - Reiniciar la aplicación" -ForegroundColor Cyan
    Write-Host "  logs         - Ver logs en tiempo real" -ForegroundColor Cyan
    Write-Host "  status       - Ver estado de contenedores" -ForegroundColor Cyan
    Write-Host "  shell        - Abrir shell en el contenedor" -ForegroundColor Cyan
    Write-Host "  clean        - Limpiar todo (contenedores, imágenes, volúmenes)" -ForegroundColor Cyan
    Write-Host "  generate-jwt - Generar un JWT secret" -ForegroundColor Cyan
    Write-Host "  help         - Mostrar esta ayuda" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Ejemplo: .\docker-helper.ps1 start" -ForegroundColor Yellow
}

# Main
switch ($Command.ToLower()) {
    "build" {
        Build-Image
    }
    "start" {
        Start-App
    }
    "stop" {
        Stop-App
    }
    "restart" {
        Restart-App
    }
    "logs" {
        Show-Logs
    }
    "status" {
        Show-Status
    }
    "shell" {
        Open-Shell
    }
    "clean" {
        Clean-All
    }
    "generate-jwt" {
        Generate-JWT
    }
    "help" {
        Show-Help
    }
    default {
        Print-Error "Comando desconocido: $Command"
        Write-Host ""
        Show-Help
        exit 1
    }
}
