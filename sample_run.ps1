$containerName = "sealift"
if (docker container inspect $containerName 2>$null) {
    Write-Host "container $containerName exists; removing it"
    docker rm -f $containerName
    docker image prune -f
}

docker run -d `
    --name $containerName `
    -e "ENDPOINT_URL=https://mydomain.com/sealift-webhook" `
    -e "VERIFICATION_TOKEN=<>" `
    -e "PORT=:443" `
    -e "EBAY_CLIENT_ID=<>" `
    -e "EBAY_CLIENT_SECRET=<>" `
    -e "EBAY_URL=https://apiz.ebay.com" `
    -e "EBAY_AUTH_URL=https://api.ebay.com/identity/v1/oauth2/token" `
    -e "EBAY_AUTH_REDIRECT_URI=<>" `
    -e "EBAY_SIGN_IN=<>" `
    -e "EBAY_TRAD_DLL_URL=https://api.ebay.com/ws/api.dll" `
    -e "EBAY_SIGN_IN=<>" `
    -e "MONGO_URI=mongodb://host.docker.internal:27017" `
    -e "FRONTEND_URL=http://localhost:3000" `
    -p "443:443" `
    "sealift:latest"

if ($LASTEXITCODE -eq 0) {
    Write-Output "container started successfully."
} else {
    Write-Error "docker run failed with exit code: $LASTEXITCODE"
}

docker logs $containerName