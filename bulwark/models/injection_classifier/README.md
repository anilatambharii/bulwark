# Injection Classifier

This directory holds the fine-tuned BERT-class classifier that powers the
ML-augmented detection path in `bulwark.core.detector.InjectionDetector`.

## Default behavior

If no model is present, Bulwark detection still works — it falls back to the
deterministic pattern catalog defined in `bulwark/utils/patterns.py`. The ML
path is **opt-in** and additive: it improves recall on novel phrasings the
regex catalog cannot anticipate, but is never required for the framework to
function.

## Provisioning a model

Two supported workflows:

1. **Hugging Face Hub** — set `DetectorConfig.model_path` to a model name
   like `protectai/deberta-v3-base-prompt-injection`, install the `[ml]`
   extra, and Bulwark will download on first use.

2. **Local fine-tune** — run your own training pipeline and write the
   exported `pytorch_model.bin` / `config.json` / tokenizer files into this
   directory. Set `DetectorConfig.model_path` to
   `bulwark/models/injection_classifier`.

## Training data

Recommended public datasets:

- [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
- [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions)
- [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification)

Augment with your own red-team corpus before deploying to production.

## Security note

A fine-tuned classifier is one signal in a defense-in-depth stack; never
treat its output as authoritative. The pattern catalog and the RBAC layer
remain the load-bearing controls.
