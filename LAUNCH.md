# Bulwark — Launch Checklist

Targeted distribution plan to maximize discovery by the buyer profile (AI
safety / agent security teams at Google, NVIDIA, Anthropic) and the
operator profile (CISOs at regulated companies running production agents).

## TL;DR — order of operations

1. **Publish to PyPI** (1 hour, today)
2. **Push HuggingFace Space + model card** (1 hour, today)
3. **Submit to OWASP, awesome-lists, package indexes** (2 hours, this week)
4. **Public launch** — HN, dev.to, Twitter/X, LinkedIn, Reddit (2 hours, day-of)
5. **Newsletters and curated lists** (passive, this month)
6. **Conference / academic** — arXiv, DEF CON CFP, RSA CFP (longer lead, this quarter)
7. **Direct outreach** — Anthropic, NVIDIA, Google AI safety contacts (this month)

---

## Phase 1 — Package availability (do these first)

### 1.1 PyPI

The `pyproject.toml` and `.github/workflows/publish.yml` are already wired.
Two paths:

**Path A — manual, fastest first publish:**

```bash
# 1. Create a PyPI account at https://pypi.org/account/register/
# 2. Generate an API token: https://pypi.org/manage/account/token/
#    Scope it to "Entire account" for the first upload (PyPI's project-
#    scoped tokens require an existing project).
# 3. Build and upload:
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/* --username __token__ --password <pypi-token>
```

**Path B — preferred long-term, OIDC trusted publishing:**

```bash
# 1. Create the PyPI project once (Path A above), then:
# 2. Go to https://pypi.org/manage/project/bulwark-agent-security/settings/publishing/
# 3. Add a trusted publisher:
#      Owner:        anilatambharii
#      Repository:   bulwark
#      Workflow:     publish.yml
#      Environment:  pypi
# 4. From now on, push a tag (`git tag v0.1.0 && git push --tags`) and
#    .github/workflows/publish.yml does the rest.
```

Confirmation: `pip install bulwark-agent-security` works from any machine.

### 1.2 conda-forge (defer, but file the recipe)

After PyPI is live for ~2 weeks, submit a recipe to conda-forge so users
on `conda install` can pick it up. Steps live at
https://conda-forge.org/docs/maintainer/adding_pkgs.html. Don't do this
day-1; do it once you have ~50 PyPI downloads/day.

---

## Phase 2 — HuggingFace presence

HuggingFace is **the** discovery surface for the AI/ML research crowd.
Anthropic, Google DeepMind, and NVIDIA AI safety researchers all browse it
daily. Two artifacts to publish:

### 2.1 HuggingFace Space (interactive demo)

Detailed steps in [`huggingface/space/DEPLOY.md`](huggingface/space/DEPLOY.md).

URL when live: `https://huggingface.co/spaces/<owner>/bulwark-demo`

### 2.2 HuggingFace model card (placeholder + future weights)

Detailed steps in [`huggingface/model/PUBLISH.md`](huggingface/model/PUBLISH.md).

URL when live: `https://huggingface.co/<owner>/injection-classifier`

The model card alone (no weights) is worth shipping immediately because
the tag pages it appears on (`prompt-injection`, `llm-security`,
`guardrails`) are routinely scanned by the buyer profile.

---

## Phase 3 — Curated lists and indexes (low effort, multi-month tail)

Submit a one-line PR or issue to each. Most are merged within 48 hours.

### Security / AI safety

- [ ] [`awesome-llm-security`](https://github.com/corca-ai/awesome-llm-security)
- [ ] [`awesome-prompt-injection`](https://github.com/FonduAI/awesome-prompt-injection)
- [ ] [`awesome-langchain`](https://github.com/kyrolabs/awesome-langchain) — Security section
- [ ] [`awesome-mcp`](https://github.com/punkpeye/awesome-mcp-servers) — Security tooling section
- [ ] [`awesome-ai-security`](https://github.com/RiccardoBiosas/awesome-ai-security)
- [ ] [`awesome-llm-supply-chain-security`](https://github.com/llmsecnet/awesome-llm-supply-chain-security)
- [ ] [`awesome-llmops`](https://github.com/tensorchord/Awesome-LLMOps)

### OWASP

- [ ] [OWASP LLM Top 10 — Tools list](https://owasp.org/www-project-top-10-for-large-language-model-applications/llm-top-10-governance-doc/) — file an issue/PR to add Bulwark to LLM01 (Prompt Injection) tooling
- [ ] [OWASP Project Incubator](https://owasp.org/www-policy/operational/projects.html) — apply for incubator status; non-trivial process but enormous credibility

### Compliance / GRC directories

- [ ] [Vanta integrations](https://www.vanta.com/integrations) — apply once you have a hosted product
- [ ] [Drata marketplace](https://drata.com/integrations) — same
- [ ] [Tugboat Logic / OneTrust] — same; defer until commercial tier

### Python ecosystem

- [ ] [Python Package Index](https://pypi.org) — done in Phase 1
- [ ] [GitHub Topics](https://github.com/topics) — set repo topics:
      `ai-security`, `prompt-injection`, `agent-security`, `mcp`,
      `llm-security`, `guardrails`, `hipaa`, `soc2`, `python`, `cybersecurity`

---

## Phase 4 — Public launch (the day all of the above is live)

### Hacker News

Single Show HN post. Title format that has worked historically for
security tooling:

> **Show HN: Bulwark — open-source defense framework for AI agents (HIPAA / SOC 2 / NERC CIP)**

Body: 2 paragraphs (problem, solution), one code snippet, link to repo +
HF Space. **Post Tuesday or Wednesday morning Pacific.** First comment from
your own account: "I'm the maintainer; happy to answer technical questions."

### Reddit

- [ ] r/MachineLearning — `[P]` post (project)
- [ ] r/Python — Show & tell
- [ ] r/cybersecurity — focus on the compliance angle
- [ ] r/LocalLLaMA — the agent-security angle resonates here
- [ ] r/programming — broader audience
- [ ] r/devops — RBAC + audit angle

### Twitter / X

Thread of 6–8 tweets:

1. The problem (1 tweet, hook)
2. The five-layer architecture (1 tweet, ASCII diagram)
3. A code snippet (1 tweet, screenshot)
4. The attack-scenarios demo output (1 tweet, screenshot)
5. The compliance angle (1 tweet)
6. Comparison to existing tools (1 tweet)
7. Links: GitHub + HF Space + PyPI (1 tweet)
8. "Built by …, available now, Apache 2.0" (1 tweet)

Tag: `@AnthropicAI @huggingface @nvidia @GoogleAI @owasp_llm_top10`.

### LinkedIn

Single post targeting CISOs / heads of AI / compliance officers. Link
straight to `docs/COMPLIANCE.md` rather than the README — that's the
language they speak.

### dev.to / Medium / Substack

- [ ] dev.to — "Building production AI agents that don't get hijacked"
- [ ] Medium / Towards Data Science — same content, different audience
- [ ] Your own Substack if you have one

---

## Phase 5 — Newsletters and curated weeklies (passive)

Submit to (each has a public submission form or a maintainer email):

- [ ] [TLDR AI](https://tldr.tech/ai) — high-signal AI roundup, ~500K readers
- [ ] [The Batch (DeepLearning.AI)](https://www.deeplearning.ai/the-batch/) — Andrew Ng's weekly
- [ ] [Last Week in AI](https://lastweekin.ai/)
- [ ] [Import AI](https://jack-clark.net/) — Jack Clark (Anthropic co-founder) reads + occasionally promotes via this newsletter
- [ ] [The Sequence](https://thesequence.substack.com/)
- [ ] [Latent Space](https://www.latent.space/)
- [ ] [Risky.Biz](https://risky.biz/) — security industry newsletter
- [ ] [tl;dr sec](https://tldrsec.com/) — security-focused, perfect audience
- [ ] [Pragmatic Engineer (Gergely Orosz)](https://newsletter.pragmaticengineer.com/) — engineering leadership
- [ ] [Last Week in AI Security](https://aisecurity.news/) (if exists; the niche has multiple contenders)

---

## Phase 6 — Academic / conference

Long lead, high credibility. Treat as parallel-track to the launch.

### arXiv preprint

- [ ] Write a 6-page paper: "Bulwark: A Five-Layer Defense Framework for
      LLM Agents in Regulated Industries"
- [ ] cs.CR + cs.LG categories
- [ ] Cite Greshake et al. (indirect prompt injection), Anthropic's
      computer-use paper, Google's April 2026 agent threat catalog
- [ ] Submit to arXiv — instant indexing in Google Scholar, Semantic Scholar,
      Papers with Code

### Conference CFPs

- [ ] **DEF CON AI Village** — paper or workshop
- [ ] **Black Hat USA / Briefings** — high-credibility venue for CISO audience
- [ ] **RSA Conference** — same
- [ ] **NeurIPS Workshop on AI Safety** — research audience
- [ ] **ICML Workshop on Adversarial ML** — research audience
- [ ] **USENIX Security** — academic CS security audience

### Industry working groups

- [ ] **MITRE ATLAS** — adversarial ML threat matrix; submit Bulwark
      mitigations against ATLAS techniques
- [ ] **OWASP LLM Top 10** — ongoing project; volunteer as a contributor
- [ ] **NIST AI Risk Management Framework** — submit Bulwark as a control
      reference for AI RMF Govern / Manage / Measure functions
- [ ] **Cloud Security Alliance — AI Working Group**
- [ ] **IEEE Standards — P3119 (procurement of AI/ML systems)** — relevant to
      the procurement-side angle

---

## Phase 7 — Direct outreach (the buyer)

The original strategic goal was acquisition by Google / NVIDIA / Anthropic.
This is the outreach plan.

### Anthropic

- [ ] **Built with Claude showcase**: https://www.anthropic.com/customers
      — submit Bulwark via their partnerships email
- [ ] **Anthropic Trust & Safety**: trust-safety@anthropic.com — direct
      pitch with a 1-pager linking the COMPLIANCE.md
- [ ] **Constitutional AI / Alignment team**: post in their Discord or
      tag relevant researchers (Daniela Amodei, Sam McCandlish, Jared Kaplan)
      on Twitter when launching
- [ ] **MCP team**: contributors @ modelcontextprotocol.io — Bulwark's MCP
      integration is directly relevant to their security narrative
- [ ] **Apply to Anthropic Startups program** if eligible

### Google

- [ ] **Google AI Safety**: post on the AI Safety Camp / METR / Google DeepMind
      mailing lists
- [ ] **Vertex AI Marketplace**: submit as a partner product once hosted tier exists
- [ ] **Google Cloud Run marketplace**: same
- [ ] **Google for Startups Cloud program**: $200K cloud credit if you fit
- [ ] Specific researchers to tag: @paulchristiano, @ShaneLegg
- [ ] **Google's Secure AI Framework (SAIF)**: submit Bulwark as a reference
      implementation

### NVIDIA

- [ ] **NVIDIA NeMo Guardrails**: file a PR linking Bulwark as a complementary
      tool — they're explicitly looking for the agent-security niche
- [ ] **NVIDIA AI Enterprise Marketplace**: partner application
- [ ] **NVIDIA Inception program**: free tier for AI startups, gives access
      to their go-to-market team

### Hyperscaler-adjacent

- [ ] **AWS Bedrock partner integrations**
- [ ] **Microsoft Azure AI Studio partner directory**
- [ ] **Databricks partner connect**

### Investor-as-distribution

- [ ] **Y Combinator** — apply to the next batch; OSS-core security tooling
      is a known-good shape there
- [ ] **a16z** — they explicitly fund OSS infra (a16z OSS portfolio)
- [ ] **Bessemer** — security + OSS portfolio
- [ ] **Greylock** — has invested in agent infrastructure
- [ ] **South Park Commons** — fellowship covers exactly this profile
- [ ] **Lightspeed** — security portfolio (Snyk, etc.)

---

## What "success" looks like at each milestone

| Day | Signal |
|-----|--------|
| Day 0 | PyPI live, GitHub repo public, HF artifacts pushed |
| Day 7 | 100+ GitHub stars, 1+ awesome-list inclusions |
| Day 30 | 500+ GitHub stars, 1,000+ PyPI downloads, 1+ newsletter mention |
| Day 90 | 2,000+ stars, 10,000+ downloads, 3+ design partners, 1+ conference acceptance |
| Day 180 | 5,000+ stars, recurring contributors, 1+ inbound from Anthropic / Google / NVIDIA |
| Day 365 | The default agent-security framework on the regulated-AI shortlist; first commercial deal or acquisition conversation |

---

## What NOT to do

- **Don't optimize the licensing now.** Apache 2.0 is correct. Don't add
  BSL, SSPL, or commercial-use restrictions before you have users.
- **Don't build hosted Bulwark Cloud yet.** Wait until 1,000+ active deployments
  ask for it. Premature SaaS = wasted runway.
- **Don't sign exclusive distribution deals.** Especially with cloud
  hyperscalers. Vendor neutrality is the marketing.
- **Don't take low-quality VC money.** A wrong investor at this stage
  steers you away from the buyer profile (regulated enterprise).
- **Don't argue with detractors on HN.** Reply once with substance, then
  let the work speak.
