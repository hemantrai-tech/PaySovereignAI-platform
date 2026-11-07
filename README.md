# PaySovereignAI — AI purchasing with user-controlled money

PaySovereignAI is a hackathon prototype for policy-gated agentic commerce. A user describes a purchase in natural language. OpenAI Structured Outputs selects a product ID from a small, fixed catalog. The server ignores model-supplied prices and independently checks the catalog item against the user's per-transaction, rolling daily, rolling 30-day, merchant, and approval rules. If the request is allowed and any required human approval is complete, the server creates a PayPal **sandbox** order. The buyer approves it at PayPal; the server then verifies and captures that order through the PayPal Orders v2 API.

The app separates three decisions: the AI recommends a catalog item; the deterministic policy engine authorizes or blocks it; PayPal reports the sandbox payment state. The AI cannot alter policy, product price, merchant identity, or payment status. A configured API key is required to run the AI and PayPal checkout paths.

## What works

- Natural-language product matching through OpenAI Chat Completions with strict JSON Schema output. The model can return only a fixed catalog ID or no match.
- Server-side validation of the returned catalog ID. Product name, merchant, currency, and price always come from the Python catalog.
- Independent policy enforcement for transaction maximum, rolling 24-hour and 30-day budgets, allowlist or restriction list, approval threshold, and new-merchant approvals.
- Fingerprinted, single-use human approvals; the policy is re-evaluated when a user approves.
- PayPal sandbox OAuth, Orders v2 order creation, buyer approval redirect, server-side capture, and capture verification. The server checks the returned PayPal order ID, proposal ID, amount, currency, order status, and completed capture before recording payment success.
- SQLite records, secure password hashing, protected session cookies, approval queue, transaction history, and audit events.
- Local run instructions. No Python packages or Node modules are required for the backend.

## Run locally

**Requirements:** Python 3.10 or newer and internet access for the OpenAI and PayPal sandbox APIs.

1. Copy `.env.example` to `.env` in the project root.
2. Add an OpenAI API key and PayPal sandbox REST app client ID and secret to `.env`. Never commit `.env` or place provider secrets in browser code.
3. Keep `PAYPAL_ENVIRONMENT=sandbox`. For local use, keep `APP_ORIGIN=http://127.0.0.1:8000`.
4. From the project root, run:

   ```sh
   python backend/main.py
   ```

5. Open <http://127.0.0.1:8000>, create an account, and try the AI Agent view.
6. To complete checkout, create a PayPal sandbox buyer in the PayPal Developer Dashboard and sign into PayPal with that buyer when redirected. Use the sandbox seller credentials from the REST app only on the server.

New accounts use a safe sample policy: USD 50 per transaction, USD 100 rolling daily, USD 1,000 rolling 30-day, `office-grove` allowlisted, approval at USD 35, and approval required for a new merchant. The sample catalog includes a recycled paper set ($18.50), desk lamp ($64), travel mug ($24), and headphones ($149). For example, the desk lamp exceeds the default per-transaction cap and should be blocked before checkout. Adjust the policy in the Policies view to explore other paths.

## Provider setup

### OpenAI

Create an API key in the [OpenAI platform](https://platform.openai.com/api-keys), set `OPENAI_API_KEY`, and optionally choose a supported model with `OPENAI_MODEL` (default: `gpt-4o-mini`). The user's natural-language request is sent to OpenAI for catalog matching. This app does not store the raw request in its activity log. Review OpenAI's current API/data terms before using real or sensitive text.

### PayPal

In the [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/), create or select a REST app in **Sandbox** and copy its sandbox client ID and secret to the server environment. Create a sandbox business account for the app and a sandbox personal account for the buyer. The application intentionally rejects non-sandbox `PAYPAL_ENVIRONMENT` values. The REST secret is never sent to the browser.

For a hosted setup, deploy the Python API and static site separately. Configure these API-server variables: `OPENAI_API_KEY`, `OPENAI_MODEL`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_ENVIRONMENT=sandbox`, `APP_ORIGIN=<the HTTPS Netlify site URL>`, `HOST=0.0.0.0`, `HTTPS=1`, and a persistent `DATA_DIR`. Configure Netlify's `API_ORIGIN` as the HTTPS API base URL and redeploy. See `render.yaml` and `netlify.toml` for deployment wiring. Do not publish credentials in this repository or submission text.

## Architecture

- `site/index.html` — public landing page, authentication screens, policy dashboard, AI agent, approvals, and transaction view.
- `backend/main.py` — Python standard-library HTTP API, SQLite persistence, OpenAI catalog matching, server policy enforcement, PayPal OAuth and Orders v2 flow.
- `backend/schema.sql` — reference schema; the service initializes its tables on startup.
- `netlify/functions/api-proxy.mjs` — same-origin proxy from the static site to the separately hosted API.
- `render.yaml` — Render API blueprint. Persistent disks require an eligible paid Render service; check current provider pricing before deploying.
- `.env.example` — local configuration template without credentials.
- `LICENSE` — MIT License.

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/register`, `/api/login` | Create a demo user or sign in |
| `GET` | `/api/dashboard` | Read user's policies, proposals, approvals, and payment records |
| `POST` | `/api/agent/propose` | Ask OpenAI to select a catalog item and run server policy checks |
| `POST` | `/api/propose` | Submit a fixed catalog item directly to server policy checks |
| `POST` | `/api/policy` | Save spending and merchant rules |
| `POST` | `/api/approval/:id` | Approve or reject an eligible proposal |
| `POST` | `/api/paypal/create-order` | Recheck policy and create a PayPal sandbox order |
| `POST` | `/api/paypal/capture-order` | Verify and capture an approved sandbox order |
| `POST` | `/api/paypal/cancel-order` | Record a buyer-cancelled sandbox checkout |
| `GET` | `/healthz` | Health check |

## Limitations and safe use

This is a hackathon prototype, not a production financial control system. It only has a small fixed product catalog; it does not search the live web, purchase arbitrary goods, or operate an autonomous PayPal agent. Users explicitly start checkout, and PayPal buyer approval is required before server-side capture. All payments are sandbox-only; no real funds move.

The API keeps sessions in process memory, so a server restart signs users out. SQLite is intended for the single-instance demo. There is no production-grade rate limiting, password reset, email verification, monitoring, fraud tooling, or independent security audit. Do not use real payment credentials, sensitive personal information, or real spending decisions. Provide provider credentials through a private environment, never a public commit.

The API server sends the purchase request to OpenAI. Model output can be wrong; the fixed catalog validation and independent server policy are the enforcement boundaries. The app has not been independently security audited and should not be exposed as a production financial service.

## Links

- **Public source repository:** <https://github.com/hemantrai-tech/PaySovereignAI-platform>
- **Project submission:** <https://devpost.com/software/paysovereign-ai>
- **Hackathon rules:** <https://paypalaihackathon.devpost.com/rules>
- **PayPal Orders v2 integration:** <https://developer.paypal.com/api/rest/integration/orders-api>
- **OpenAI Structured Outputs:** <https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat>

## Project context

Created for the PayPal AI Hackathon. The prototype combines a model-backed catalog match, deterministic server policy checks, required human approval for selected requests, and buyer-approved PayPal sandbox checkout. See the Devpost project story for the build process and current demonstration notes.
