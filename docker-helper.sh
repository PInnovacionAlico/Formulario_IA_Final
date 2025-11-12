#!/bin/bash

# Script de utilidad para Docker
# Uso: ./docker-helper.sh [comando]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  Formulario IA - Docker Helper${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker no está instalado"
        echo "Visita: https://www.docker.com/get-started"
        exit 1
    fi
    print_success "Docker encontrado"
}

check_env() {
    if [ ! -f .env ]; then
        print_warning "Archivo .env no encontrado"
        echo "Creando .env desde .env.example..."
        cp .env.example .env
        print_warning "Por favor, edita .env con tus valores reales antes de continuar"
        exit 1
    fi
    print_success "Archivo .env encontrado"
}

build() {
    print_header
    echo "🔨 Construyendo imagen Docker..."
    docker-compose build
    print_success "Imagen construida exitosamente"
}

start() {
    print_header
    check_docker
    check_env
    echo "🚀 Iniciando aplicación..."
    docker-compose up -d
    print_success "Aplicación iniciada"
    echo ""
    echo "📍 Accede a: http://localhost:3000"
    echo "📊 Ver logs: ./docker-helper.sh logs"
}

stop() {
    print_header
    echo "🛑 Deteniendo aplicación..."
    docker-compose down
    print_success "Aplicación detenida"
}

restart() {
    print_header
    echo "🔄 Reiniciando aplicación..."
    docker-compose restart
    print_success "Aplicación reiniciada"
}

logs() {
    echo "📋 Mostrando logs (Ctrl+C para salir)..."
    docker-compose logs -f
}

status() {
    print_header
    echo "📊 Estado de los contenedores:"
    echo ""
    docker-compose ps
}

clean() {
    print_header
    print_warning "Esto eliminará todos los contenedores, imágenes y volúmenes"
    read -p "¿Estás seguro? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v --rmi all
        print_success "Limpieza completada"
    else
        echo "Cancelado"
    fi
}

shell() {
    print_header
    echo "🐚 Abriendo shell en el contenedor..."
    docker-compose exec app sh
}

generate_jwt() {
    print_header
    echo "🔑 Generando JWT Secret..."
    JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    echo ""
    print_success "JWT Secret generado:"
    echo ""
    echo "$JWT_SECRET"
    echo ""
    echo "Copia este valor a tu archivo .env"
}

help() {
    print_header
    echo "Comandos disponibles:"
    echo ""
    echo "  build       - Construir la imagen Docker"
    echo "  start       - Iniciar la aplicación"
    echo "  stop        - Detener la aplicación"
    echo "  restart     - Reiniciar la aplicación"
    echo "  logs        - Ver logs en tiempo real"
    echo "  status      - Ver estado de contenedores"
    echo "  shell       - Abrir shell en el contenedor"
    echo "  clean       - Limpiar todo (contenedores, imágenes, volúmenes)"
    echo "  generate-jwt - Generar un JWT secret"
    echo "  help        - Mostrar esta ayuda"
    echo ""
    echo "Ejemplo: ./docker-helper.sh start"
}

# Main
case "$1" in
    build)
        build
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    logs)
        logs
        ;;
    status)
        status
        ;;
    shell)
        shell
        ;;
    clean)
        clean
        ;;
    generate-jwt)
        generate_jwt
        ;;
    help|--help|-h|"")
        help
        ;;
    *)
        print_error "Comando desconocido: $1"
        echo ""
        help
        exit 1
        ;;
esac
