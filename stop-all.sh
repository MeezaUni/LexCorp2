#!/bin/bash
# Stop all LexCorp services

echo "Stopping all LexCorp services..."

if [ -f .pids ]; then
    while read pid; do
        if ps -p $pid > /dev/null 2>&1; then
            echo "Killing process $pid"
            kill -9 $pid 2>/dev/null || true
        fi
    done < .pids
    rm .pids
fi

# Cleanup ports just in case
lsof -ti:8545 | xargs kill -9 2>/dev/null || true
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

echo "All services stopped."
