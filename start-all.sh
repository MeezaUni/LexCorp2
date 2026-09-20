#!/bin/bash
# LexCorp Full Stack Startup Script

echo "========================================================================"
echo "LexCorp SIH 2026 Platform - Starting All Services"
echo "========================================================================"
echo ""

# Kill any existing processes on required ports
echo "[1/5] Cleaning up existing processes..."
lsof -ti:8545 | xargs kill -9 2>/dev/null || true
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true
sleep 2

# Start Hardhat Node
echo ""
echo "[2/5] Starting Hardhat Blockchain Node (localhost:8545)..."
cd contracts
npx hardhat node > ../logs/hardhat.log 2>&1 &
HARDHAT_PID=$!
echo "Hardhat PID: $HARDHAT_PID"
cd ..
sleep 5

# Deploy Smart Contracts
echo ""
echo "[3/5] Deploying Smart Contracts..."
cd contracts
npx hardhat run scripts/deploy.js --network localhost > ../logs/deploy.log 2>&1
DEPLOY_STATUS=$?
if [ $DEPLOY_STATUS -eq 0 ]; then
    echo "[OK] Smart contracts deployed successfully"
else
    echo "[ERROR] Contract deployment failed. Check logs/deploy.log"
fi
cd ..
sleep 2

# Start Backend API
echo ""
echo "[4/5] Starting FastAPI Backend (localhost:8000)..."
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload > ../logs/backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"
cd ..
sleep 3

# Start Event Indexer
echo ""
echo "[4.5/5] Starting Blockchain Event Indexer..."
cd backend
python -m app.services.event_indexer > ../logs/indexer.log 2>&1 &
INDEXER_PID=$!
echo "Indexer PID: $INDEXER_PID"
cd ..
sleep 2

# Start Frontend
echo ""
echo "[5/5] Starting Vite Frontend (localhost:5173)..."
cd frontend
npm run dev > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"
cd ..
sleep 3

# Save PIDs for later cleanup
echo "$HARDHAT_PID" > .pids
echo "$BACKEND_PID" >> .pids
echo "$INDEXER_PID" >> .pids
echo "$FRONTEND_PID" >> .pids

echo ""
echo "========================================================================"
echo "ALL SERVICES STARTED SUCCESSFULLY"
echo "========================================================================"
echo ""
echo "Service Status:"
echo "  - Hardhat Node:    http://localhost:8545  (PID: $HARDHAT_PID)"
echo "  - Backend API:     http://localhost:8000  (PID: $BACKEND_PID)"
echo "  - Event Indexer:   Running in background (PID: $INDEXER_PID)"
echo "  - Frontend App:    http://localhost:5173  (PID: $FRONTEND_PID)"
echo ""
echo "Logs available in ./logs/ directory"
echo "  - hardhat.log   - Blockchain node output"
echo "  - backend.log   - FastAPI server logs"
echo "  - indexer.log   - Event indexer logs"
echo "  - frontend.log  - Vite dev server logs"
echo ""
echo "Admin Credentials:"
echo "  Wallet:      0x95ea9708BCf136d710A4b8e76FE20F895ecA003A"
echo "  Private Key: 0x74745bf7bdc8ae82687ac8ac993fd752130fe45ed8d126818414105b71244809"
echo ""
echo "To stop all services: ./stop-all.sh"
echo "========================================================================"
