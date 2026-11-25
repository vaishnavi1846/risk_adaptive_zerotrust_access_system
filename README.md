# Risk-Adaptive Zero-Trust Access Control

Mid-term project implementation built with FastAPI, SQLAlchemy, PostgreSQL, JWT, Argon2 password hashing, and React/Vite.

## Database and backend setup

Create the PostgreSQL database if it does not already exist:

```sql
CREATE DATABASE risk_adaptive_zerotrust;
```

From `backend/`, create and activate a virtual environment, install `requirements.txt`, copy `.env.example` to `.env`, and replace the values. Set `DATABASE_URL` to the local PostgreSQL connection string, `JWT_SECRET` to a generated random secret, and `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` to provision the first administrator. Admin credentials are never seeded in source code. Tables, a default policy, and four demonstration resources are created on first startup.

Windows PowerShell example:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env with your PostgreSQL login, JWT secret, and bootstrap admin credentials.
uvicorn app.main:app --reload
```

API docs: <http://localhost:8000/docs> · Health check: <http://localhost:8000/health>

The sample `DATABASE_URL` uses local peer/trust authentication (`postgresql+psycopg:///...`). If PostgreSQL requires a password, use `postgresql+psycopg://USER:PASSWORD@localhost:5432/risk_adaptive_zerotrust` in `.env`.

## Frontend setup

From `frontend/`:

```powershell
npm install
npm run dev
```

Open <http://localhost:5173>. Set `VITE_API_URL` before starting Vite if the backend is not at `http://localhost:8000/api`.

## Admin setup and demo

Set `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD` (at least 10 characters), `JWT_SECRET`, and the correct PostgreSQL URL in `backend/.env`. Restart the backend and log in using the configured admin email/password. Register a normal user from the login screen, then use the administrator's **Risk Simulator** page. Its scenario cards prefill the contexts; choose a user and resource and press **Evaluate Access**.

1. Trusted device, normal location/time, low sensitivity: score 2, **ALLOW**.
2. Unknown device, new location, unusual time, one failed attempt, high sensitivity: score 47, **RESTRICT**.
3. Compromised device, suspicious location, unusual time, five failed attempts, critical sensitivity: score 100, **DENY**.

The same deterministic risk engine is used for actual `/api/access-requests` and simulator `/api/risk/evaluate` requests. Real requests without an explicit time context classify UTC hours 07:00–18:59 as normal and other hours as unusual; the simulator accepts its configured time scenario. Both paths are stored with risk factors, decision, and audit events. Device trust changes through the admin Devices page affect subsequent real requests. Simulator evaluations are marked as simulated in the audit event metadata.

Normal users never receive risk fields from their dashboard/history endpoints; detailed factor breakdowns and simulator access are admin-only. This is a demonstration implementation: schema changes use SQLAlchemy `create_all`; add Alembic migrations before production use.
