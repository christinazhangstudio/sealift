$containerName = "sealift-webhook"
if (docker container inspect $containerName 2>$null) {
    Write-Host "container $containerName exists; removing it"
    docker rm -f $containerName
}

docker run -d `
    --name $containerName `
    -e "ENDPOINT_URL=https://mydomain.com/sealift-webhook" `
    -e "VERIFICATION_TOKEN=<VERIFICATION_TOKEN>" `
    -e "PORT=:443" `
    -p "443:443" `
    "sealift-webhook:latest"

if ($LASTEXITCODE -eq 0) {
    Write-Output "container started successfully."
} else {
    Write-Error "docker run failed with exit code: $LASTEXITCODE"
}

docker logs $containerName