#!/bin/bash
export DOCKER_BUILDKIT=0
export PATH="$HOME/fabric-samples/bin:$PATH"
export FABRIC_CFG_PATH="$HOME/fabric-samples/test-network/../config/"

BLOCKCERT_DIR="$HOME/certchain"
FABRIC_DIR="$HOME/fabric-samples/test-network"
CHANNEL="certchainchannel"

echo "=== CertChain Startup ==="

# Step 1 - Check/start Fabric
cd "$FABRIC_DIR"
RUNNING=$(docker ps --filter name=peer0.org1.example.com --format "{{.Names}}" 2>/dev/null)

if [ -z "$RUNNING" ]; then
  echo "[1/5] Starting Fabric network..."
  docker pull hyperledger/fabric-peer:2.5.0 --quiet 2>/dev/null
  docker tag hyperledger/fabric-peer:2.5.0 hyperledger/fabric-peer:latest 2>/dev/null
  ./network.sh up createChannel -c $CHANNEL -ca >> "$BLOCKCERT_DIR/certchain.log" 2>&1
  echo "[2/5] Deploying chaincode..."
  ./network.sh deployCC -ccn certchain -ccp "$BLOCKCERT_DIR/chaincode/" -ccl javascript -c $CHANNEL >> "$BLOCKCERT_DIR/certchain.log" 2>&1
  echo "[3/5] Copying connection profile..."
  cp organizations/peerOrganizations/org1.example.com/connection-org1.json "$BLOCKCERT_DIR/config/connection.json"
  echo "[4/5] Enrolling identities..."
  cd "$BLOCKCERT_DIR"
  node -e "const w=require('./wallet/wallet_setup');(async()=>{await w.enrollAdmin();await w.registerUser({userID:'famu-institution',role:'institution'});await w.registerUser({userID:'public-verifier',role:'verifier'});await w.registerUser({userID:'FAMU10001',role:'student'});console.log('Identities enrolled');})().catch(console.error);"
else
  echo "[1-4] Fabric already running — skipping"
  cd "$BLOCKCERT_DIR"
  [ ! -f config/connection.json ] && cp "$FABRIC_DIR/organizations/peerOrganizations/org1.example.com/connection-org1.json" config/connection.json
fi

# Step 5 - Start API
echo "[5/5] Starting API server..."
cd "$BLOCKCERT_DIR"
pkill -f "node api/server.js" 2>/dev/null; sleep 1
nohup node api/server.js >> certchain.log 2>&1 &
sleep 2

STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
if [ "$STATUS" = "200" ]; then
  echo "[✓] API running on port 3000"
else
  echo "[!] API may not be running — check certchain.log"
fi

# Optional ngrok
if [[ "$1" == "--ngrok" ]]; then
  echo "[→] Starting ngrok..."
  pkill -f ngrok 2>/dev/null
  nohup ngrok http 3000 > "$BLOCKCERT_DIR/.ngrok.log" 2>&1 &
  sleep 4
  NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | python3 -c "import sys,json;t=json.load(sys.stdin)['tunnels'];h=[x for x in t if x['proto']=='https'];print(h[0]['public_url'] if h else '')" 2>/dev/null)
  if [ -n "$NGROK_URL" ]; then
    echo ""
    echo "========================================="
    echo "  LIVE URL: $NGROK_URL"
    echo "  Set this in GUI Settings tab"
    echo "========================================="
    echo "$NGROK_URL" > "$BLOCKCERT_DIR/.ngrok_url"
  else
    echo "[!] ngrok started — check http://localhost:4040 for URL"
  fi
fi

echo ""
echo "Done. Test: curl http://localhost:3000/health"
