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
    -e "EBAY_SCOPE=<>" `
    -e "MONGO_URI=mongodb://host.docker.internal:27017" `
    -e "ATLAS_URI=<>" `
    -e "FRONTEND_URL=http://host.docker.internal:9997" `
    -e "OLLAMA_URL=http://host.docker.internal:11434" `
    -e "OPENAI_API_KEY=<>" `
    -e "AI_SIMILARITY_THRESHOLD=0.5" `
    -e "USE_SELF_HOSTED_AI=true" `
    -e "SELF_HOSTED_AI_URL=<>" `
    -e "SELF_HOSTED_AI_MODEL=qwen" `
    -e "GROQ_AI_MODEL=llama-3.3-70b-versatile" `
    -v "$($PWD.Path)/docs:/root/docs" `
    -v "$($PWD.Path)/prompts:/root/prompts" `
    -p "443:443" `
    "sealift:latest"

if ($LASTEXITCODE -eq 0) {
    Write-Output "container started successfully."
} else {
    Write-Error "docker run failed with exit code: $LASTEXITCODE"
}

docker logs $containerName