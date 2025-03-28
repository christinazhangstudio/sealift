# SEALIFT


for any temporary testing at a web-exposed URL:
```
ngrok.exe http --host-header=rewrite http://localhost:443
```

```
docker build -t sealift-webhook:latest .
docker tag sealift-webhook:latest czhang19/christina:sealift
docker push czhang19/christina:sealift
```