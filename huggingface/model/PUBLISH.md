# Publishing the Bulwark model card to HuggingFace

Even before a trained checkpoint exists, publish the **model card** so that
the project shows up in HuggingFace's tag-based discovery
(`prompt-injection`, `llm-security`, `agent-security`). This is one of the
highest-leverage discovery surfaces for the Anthropic / NVIDIA / Google AI
research crowd.

## 1. Create the model repository

1. Sign in to https://huggingface.co.
2. Profile menu → **New Model**.
3. Owner: `bulwark-security` (create the org first if it doesn't exist) or
   your personal namespace.
4. Model name: `injection-classifier`.
5. License: **Apache 2.0**.
6. Visibility: **Public**.
7. Click **Create Model**.

## 2. Push the model card

```bash
# from the bulwark repo root
git clone https://huggingface.co/<YOUR-OWNER>/injection-classifier /tmp/bulwark-model
cp huggingface/model/README.md /tmp/bulwark-model/README.md
cd /tmp/bulwark-model
git add README.md
git commit -m "Initial model card"
git push
```

## 3. After training a real checkpoint

Once Bulwark v0.2.0 ships with `scripts/train_classifier.py`, the trained
weights go in the same repo:

```bash
# from /tmp/bulwark-model
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./pytorch_model.bin
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./config.json
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./tokenizer_config.json
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./tokenizer.json
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./special_tokens_map.json
huggingface-cli upload <YOUR-OWNER>/injection-classifier ./vocab.txt
```

Update the README.md to remove the "v0 placeholder" notice and add real
benchmark numbers.

## 4. Discoverability

The model card alone (no weights yet) places Bulwark in:

- HF tag pages for `prompt-injection`, `llm-security`, `guardrails`
  (these get checked by AI safety researchers daily)
- Search results for "agent security", "injection classifier"
- The Spaces ↔ Models cross-reference graph
