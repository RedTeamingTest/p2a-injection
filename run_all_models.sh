#!/bin/bash
set -e
cd /home/qyb/TongBu/prompt_to_api_call_injection/demo
export DEMO_URL=http://localhost:8889

MODELS=("qwen2.5:latest" "ministral-3:latest" "qwen2.5-coder:14b")
SYSTEMS=("portal" "ecommerce" "gitea" "homeassistant")

TOTAL=$((${#MODELS[@]} * ${#SYSTEMS[@]}))
COUNT=0
START=$(date +%s)

for model in "${MODELS[@]}"; do
    for system in "${SYSTEMS[@]}"; do
        COUNT=$((COUNT + 1))
        echo ""
        echo "============================================================"
        echo "  [$COUNT/$TOTAL] Model: $model | System: $system"
        echo "  Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        
        python3 run_rq1_real.py --system "$system" --n 10 --model "$model" 2>&1
        
        echo "  Finished: $(date '+%Y-%m-%d %H:%M:%S')"
    done
done

END=$(date +%s)
ELAPSED=$(( (END - START) / 60 ))
echo ""
echo "============================================================"
echo "  ALL EXPERIMENTS COMPLETED in ${ELAPSED} minutes"
echo "============================================================"
