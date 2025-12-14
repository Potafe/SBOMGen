Write-Host "Building scanner base image..."
docker build -f Dockerfile.scanners -t yazat/scanners:latest .

Write-Host "Building main application image..."
docker build -t yazat/sbomgen:latest .

Write-Host "Images built successfully!"
Write-Host ""
Write-Host "To push to registry:"
Write-Host "  docker push yazat/scanners:latest"
Write-Host "  docker push yazat/sbomgen:latest"
Write-Host ""
Write-Host "To run with docker-compose:"
Write-Host "  docker-compose up"