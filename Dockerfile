# Lightweight on purpose: SAMPLE_MODE (LLM_PROVIDER=rule_based) needs
# nothing beyond the Python standard library. The three provider packages
# below are only exercised if you actually set LLM_PROVIDER to anthropic,
# openai, or ollama in .env - installing them at build time (not at
# runtime) keeps the container's execution fast and predictable, per the
# hackathon's own runtime-discipline guidance.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py setup_zetaris.py debug_llm_certainty_only.py baseline_naive.py ./
COPY check_*.py ./
COPY agents/ ./agents/
COPY integrations/ ./integrations/
COPY data/ ./data/
COPY evaluation/ ./evaluation/
COPY input_examples/ ./input_examples/

# logs/ is created at runtime, not baked into the image, and is mounted
# as a volume in docker-compose.yml so a judge can read it from the host
# without opening a shell inside the container.
RUN mkdir -p logs

# Default: the full sample-mode run needs no credentials, no network -
# this is what a judge running the container with no setup will see.
CMD ["python3", "main.py"]
