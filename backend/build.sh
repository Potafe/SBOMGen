#!/bin/bash
set -e  # Exit on any error

echo "Building scanner base image..."
docker build -f Dockerfile.scanners -t yazat/scanners:latest .

echo "Building main application image..."  
docker build -t yazat/sbomgen:latest .

echo "Images built successfully!"
echo ""
echo "To push to registry:"
echo "  docker push yazat/scanners:latest"
echo "  docker push myorg/sbomgen:latest"
echo ""
echo "To run with docker-compose:"
echo "  docker-compose up"