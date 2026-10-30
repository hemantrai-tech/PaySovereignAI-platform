# PaySovereignAI — Netlify source bundle

This ZIP contains a Netlify static site plus a Netlify Function that proxies `/api/*` to the Python API. Netlify does not run this Python server as a site function. The backend must be deployed separately. `render.yaml` describes one supported hosting option with a persistent disk for SQLite.

## Deploy

1. Extract this ZIP and push its contents to a Git repository. Netlify manual drag-and-drop deploys are not suitable for this package because the API proxy function must be built and deployed. Connect the repository to Netlify and use the included `netlify.toml` settings.
2. Deploy the repository to Render using the included `render.yaml`. The service uses a paid `starter` instance and a 1 GB persistent disk; Render documents persistent disks as available on paid services. Review current pricing before creating the service.
3. Copy the deployed backend's HTTPS base URL from Render. In Netlify site environment variables, set `API_ORIGIN` to that URL, then trigger a new deploy.
4. Open the Netlify URL. Register an account, set a policy, and try the clearly labeled sample catalog and approval flow.

## Important limits

- This is a daily-use **policy workflow demo**, not a production financial control system. The Python API retains sessions in memory (restarts sign users out), uses SQLite and a single process, and lacks production-grade rate limiting, password reset/email verification, monitoring, and security review. Do not use it to authorize real spending or store sensitive financial information.
- PayPal order creation/capture and live AI search are not implemented. A configured PayPal credential does not make payments functional.
- The Render persistent disk is single-instance storage. Do not scale the API horizontally. Consider managed Postgres and a hardened auth/session service before relying on the service for real daily financial decisions.
- The ZIP excludes the local SQLite database and all secrets. Add secrets only in the hosting provider's environment settings.

## Local verification

Run the API from the project root with `python backend/main.py`; open `http://127.0.0.1:8000`. To run the policy tests, use `python -m unittest discover -s backend/tests`.

## Components

- `site/index.html`: public site, registration/login, and dashboard UI.
- `netlify/functions/api-proxy.mjs`: same-origin API proxy; forwards HttpOnly session cookies between the site and backend.
- `backend/main.py`: Python HTTP API and SQLite persistence.
- `backend/schema.sql`: SQLite schema reference; the service initializes its schema at startup.
- `render.yaml`: Render API host blueprint with persistent disk.
