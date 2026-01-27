#!/bin/bash

IMAGE_NAME="flaresolverr:local"
CONTAINER_NAME="flaresolverr"
PLATFORM="linux/amd64"
PORT="8191"
LOG_LEVEL="${LOG_LEVEL:-debug}"  # default to debug, override with LOG_LEVEL=info ./run.sh

echo "==> Building Docker image..."
docker build --platform $PLATFORM -t $IMAGE_NAME . || { echo "Build failed!"; exit 1; }

echo "==> Stopping existing container (if any)..."
docker stop $CONTAINER_NAME 2>/dev/null
docker rm $CONTAINER_NAME 2>/dev/null

echo "==> Starting new container (LOG_LEVEL=$LOG_LEVEL)..."
docker run -d \
  --name $CONTAINER_NAME \
  --platform $PLATFORM \
  -p $PORT:8191 \
  -e LOG_LEVEL=$LOG_LEVEL \
  --restart unless-stopped \
  $IMAGE_NAME

echo "==> Waiting for startup..."
sleep 5

echo "==> Health check..."
curl -s http://localhost:$PORT/ | python3 -m json.tool 2>/dev/null || curl -s http://localhost:$PORT/

echo ""
echo "==> Container logs (last 30 lines):"
docker logs $CONTAINER_NAME 2>&1 | tail -30

echo ""
echo "==> FlareSolverr v$(curl -s http://localhost:$PORT/ 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null) running at http://localhost:$PORT"
echo ""
echo "==> Follow logs with: docker logs -f $CONTAINER_NAME"
