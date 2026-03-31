#!/bin/bash
cd "$(dirname "$0")"
MODELS=("llama3:latest" "qwen2.5:latest" "ministral-3:latest" "qwen2.5-coder:14b")
for model in "${MODELS[@]}"; do
    echo "=========================================="
    echo "MODEL: $model | SYSTEM: directus"
    echo "=========================================="
    DEMO_URL=http://localhost:8888 OLLAMA_MODEL="$model" N_TRIALS=10 \
        python3 run_rq1_real.py --system directus --model "$model" --n 10
    echo ""
done
echo "ALL DIRECTUS EXPERIMENTS COMPLETE"
