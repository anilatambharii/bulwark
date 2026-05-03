# Deploying the Bulwark Space to HuggingFace

Manual one-time setup (account + space creation). Once the Space exists,
every push to `main` rebuilds and redeploys automatically.

## 1. Create the Space

1. Sign in to https://huggingface.co.
2. Profile menu → **New Space**.
3. Owner: `bulwark-security` (create the org first if it doesn't exist) or
   your personal account.
4. Space name: `bulwark-demo`.
5. License: **Apache 2.0**.
6. SDK: **Streamlit**.
7. Visibility: **Public**.
8. Click **Create Space**.

## 2. Push the Space contents

Spaces are git repositories. Clone the empty Space and push the contents
of this directory into it:

```bash
# from the bulwark repo root
git clone https://huggingface.co/spaces/<YOUR-OWNER>/bulwark-demo /tmp/bulwark-space
cp huggingface/space/README.md      /tmp/bulwark-space/README.md
cp huggingface/space/app.py         /tmp/bulwark-space/app.py
cp huggingface/space/requirements.txt /tmp/bulwark-space/requirements.txt
cp examples/dashboard.py            /tmp/bulwark-space/dashboard.py
```

Edit the top of the copied `app.py` so the `from examples.dashboard import main`
line becomes `from dashboard import main` (since the Space is flat).

```bash
cd /tmp/bulwark-space
git add .
git commit -m "Initial Bulwark Space"
git push
```

The build kicks off automatically; the live URL will be
`https://huggingface.co/spaces/<YOUR-OWNER>/bulwark-demo`.

## 3. Updates

After the initial push, every commit to `main` redeploys the Space. There's
no separate CI step. Build status and logs are visible at
`https://huggingface.co/spaces/<YOUR-OWNER>/bulwark-demo/logs`.

## 4. Performance / cost

The default CPU Basic tier is free; latency is fine for the playground
since each scan is < 100 ms. If you ever flip on the optional ML classifier,
upgrade to a CPU Upgrade tier (~$0.03 / hr).

## 5. Sharing

Once live, the Space URL is shareable and embeddable. It also appears in:

- HuggingFace Spaces global search (within ~24 hr)
- HuggingFace's "AI Safety" / "Security" curated collections (apply via
  https://huggingface.co/spaces?category=ai-safety)
- Anyone watching tags: `prompt-injection`, `llm-security`, `mcp`,
  `agent-security`
