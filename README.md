# Aryeh Lab

The landing page for [aryehlab.com](https://aryehlab.com). It links visitors
to Aryeh Lab services hosted on dedicated subdomains.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

## Production

The app is intended to run behind a Cloudflare Tunnel:

- `aryehlab.com` and `www.aryehlab.com` → this landing page
- `timelapse.aryehlab.com` → the Raspberry Pi timelapse service
