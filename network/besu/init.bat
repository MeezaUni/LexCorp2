@echo off
echo Starting Besu Network initialization...
bash init.sh
echo Done. To run the network: docker-compose -f docker-compose-active.yml up -d
pause
