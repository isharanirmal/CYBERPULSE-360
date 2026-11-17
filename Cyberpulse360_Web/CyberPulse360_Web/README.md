# CYBERPULSE 360 – Web Dashboard

## Run locally (VS Code)
1. Open this folder in VS Code.
2. Press **F5** (or terminal: `py serve.py`). Browser opens at http://localhost:8000

## Deploy to Vercel (public URL)
Option A – CLI:
    npm i -g vercel
    vercel login
    vercel --prod
(Accept defaults. Framework: Other. Output directory: public)

Option B – GitHub:
1. Push this folder to a GitHub repo.
2. vercel.com > Add New > Project > import repo > Deploy.

The dashboard is a single static file (public/index.html), no build step.
