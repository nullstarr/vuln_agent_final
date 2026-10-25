"""
A single place for the language-model call, swappable via the
environment variable LLM_PROVIDER (anthropic / openai / ollama / rule_based).

IMPORTANT: "rule_based" is not a test stopgap, but the officially
required example mode (SAMPLE_MODE) - it needs no key and
still produces a complete, sensible explanation, because the
actual decision (see reconciler.py, challenger.py) is never
made by the language model anyway, only the wording at the end.

"ollama" runs completely locally on your own graphics card - no
key, no cost, no outbound network request. It only needs
a running Ollama service on the same machine (see README).
"""

import collections
import os
import time

# Which model actually answered how many requests (provider/model as reported by the service). Read by main.py for the
# report footer, so a report never has to guess which model produced a sentence.
SERVED = collections.Counter()
_LAST_NVIDIA_CALL = [0.0]
# Calls that FAILED (service down, bad key, no answer). The run does not stop: the caller gets None and uses the rules,
# and the report footer says how many calls failed and why, so a fallback is never silent.
FAILURES = collections.Counter()
_WARNED = [False]


def complete(system_prompt, user_prompt):
    try:
        return _complete(system_prompt, user_prompt)
    except Exception as e:  # noqa: BLE001 - any provider error must degrade to the rules, openly
        provider = os.environ.get("LLM_PROVIDER", "rule_based").lower()
        FAILURES[f"{provider}: {type(e).__name__}: {str(e)[:100]}"] += 1
        if not _WARNED[0]:
            _WARNED[0] = True
            print(f"[warning] AI provider '{provider}' failed ({type(e).__name__}: {str(e)[:100]}). "
                  "Falling back to the rule-based check for these calls; the report says so.")
        return None


def _complete(system_prompt, user_prompt):
    provider = os.environ.get("LLM_PROVIDER", "rule_based").lower()

    if provider == "rule_based":
        # No external call - see the docstring above.
        return None

    if provider == "anthropic":
        import anthropic
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment
        resp = client.messages.create(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
            max_tokens=600,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return resp.content[0].text

    if provider == "openai":
        import openai
        client = openai.OpenAI()  # reads OPENAI_API_KEY from the environment
        resp = client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content

    if provider == "nvidia":
        # NVIDIA's hosted models (build.nvidia.com / NIM) speak the OpenAI protocol - hence the same
        # package with a different address. NOT tested against the real service (see README); model name
        # and address can change, so they are set via environment variables.
        import openai
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            raise ValueError("NVIDIA_API_KEY is missing (see .env.example and the NVIDIA folder in HackOS)")
        client = openai.OpenAI(
            base_url=os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            api_key=api_key,
        )
        # Nemotron 3.5 is a reasoning model: it writes its thinking to `reasoning_content` first and only then the answer
        # to `content`. With too few tokens `content` stays null. So: allow more tokens (NVIDIA_MAX_TOKENS) and, if the
        # model supports it, switch the thinking off (NVIDIA_ENABLE_THINKING=false). The thinking text is NEVER used as the answer.
        extra = {}
        if os.environ.get("NVIDIA_ENABLE_THINKING", "").strip().lower() in ("0", "false", "no", "off"):
            extra["chat_template_kwargs"] = {"enable_thinking": False}
        # The free endpoint limits calls per minute (we hit HTTP 429 after ~40 calls). Space the calls out
        # (NVIDIA_MIN_INTERVAL seconds, default 1.6 = ~37 per minute) and, if a 429 still comes, wait and retry.
        min_gap = float(os.environ.get("NVIDIA_MIN_INTERVAL", "1.6"))
        resp = None
        for attempt in range(6):
            wait = _LAST_NVIDIA_CALL[0] + min_gap - time.time()
            if wait > 0:
                time.sleep(wait)
            _LAST_NVIDIA_CALL[0] = time.time()
            try:
                resp = client.chat.completions.create(
                    model=os.environ.get("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct"),
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0,   # as with Ollama: deterministic for a yes/no assessment
                    max_tokens=int(os.environ.get("NVIDIA_MAX_TOKENS", "600")),
                    **({"extra_body": extra} if extra else {}),
                )
                break
            except openai.RateLimitError:
                if attempt == 5:
                    raise
                time.sleep(15 * (attempt + 1))
        content = resp.choices[0].message.content
        if not content or not content.strip():
            raise ValueError("The NVIDIA model returned no final answer (a reasoning model that ran out of tokens while thinking). "
                             "Raise NVIDIA_MAX_TOKENS (e.g. 2000) or set NVIDIA_ENABLE_THINKING=false.")
        SERVED[f"nvidia -> {getattr(resp, 'model', None) or os.environ.get('NVIDIA_MODEL', '?')}"] += 1
        return content

    if provider == "meterless":
        # Meterless Runtime (Nightshift) as the AI provider - see agents/meterless_runtime.py for the contract it follows.
        from . import meterless_runtime
        text, served = meterless_runtime.chat(system_prompt, user_prompt)
        SERVED[f"meterless -> {served}"] += 1
        return text

    if provider == "ollama":
        import ollama
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        model = os.environ.get("OLLAMA_MODEL", "llama3:latest")
        client = ollama.Client(host=host)
        resp = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            options={"temperature": 0},  # deterministic, no randomness for a yes/no assessment
        )
        return resp["message"]["content"]

    raise ValueError(f"Unknown LLM_PROVIDER: {provider}")
