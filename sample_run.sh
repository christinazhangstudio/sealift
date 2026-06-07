#!/usr/bin/env bash

# Sample / template version of run.sh (equivalent of sample_run.ps1)
# Replace the placeholder values (<>) with your real configuration before use.

set -e

CONTAINER_NAME="sealift"

if docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1; then
    echo "container $CONTAINER_NAME exists; removing it"
    docker rm -f "$CONTAINER_NAME"
    docker image prune -f
fi

# === Self-hosted AI configuration (override for local dev) ===
SELF_HOSTED_AI_CHAT_COMPLETIONS_URL="${SELF_HOSTED_AI_CHAT_COMPLETIONS_URL:-<>}"
SELF_HOSTED_AI_CHAT_COMPLETIONS_MODEL="${SELF_HOSTED_AI_CHAT_COMPLETIONS_MODEL:-qwen}"
SELF_HOSTED_EMBEDDING_URL="${SELF_HOSTED_EMBEDDING_URL:-<>}"
SELF_HOSTED_EMBEDDING_MODEL="${SELF_HOSTED_EMBEDDING_MODEL:-<>}"

# Replace this with your full eBay OAuth scope list
EBAY_SCOPE="<>"

docker run -d \
    --name "$CONTAINER_NAME" \
    -e "ENDPOINT_URL=https://mydomain.com/sealift-webhook" \
    -e "VERIFICATION_TOKEN=<>" \
    -e "PORT=:443" \
    -e "EBAY_SCOPE=$EBAY_SCOPE" \
    -e "MONGO_URI=mongodb://host.docker.internal:27017" \
    -e "ATLAS_URI=<>" \
    -e "FRONTEND_URL=http://host.docker.internal:9997" \
    -e "OPENAI_API_KEY=<>" \
    -e "AI_SIMILARITY_THRESHOLD=0.5" \
    -e "USE_SELF_HOSTED_AI=true" \
    -e "SELF_HOSTED_AI_CHAT_COMPLETIONS_URL=<>" \
    -e "SELF_HOSTED_AI_CHAT_COMPLETIONS_MODEL=qwen" \
    -e "SELF_HOSTED_EMBEDDING_URL=<>" \
    -e "SELF_HOSTED_EMBEDDING_MODEL=snowflake" \
    -e "GROQ_AI_MODEL=llama-3.3-70b-versatile" \
    -v "$PWD/docs:/root/docs" \
    -v "$PWD/prompts:/root/prompts" \
    -p "443:443" \
    "sealift:latest"

if [ $? -eq 0 ]; then
    echo "container started successfully."
else
    echo "docker run failed with exit code: $?" >&2
fi

docker logs "$CONTAINER_NAME"
