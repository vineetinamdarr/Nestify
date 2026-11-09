# Nestify

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --host 0.0.0.0
Open http://localhost:8000 (phones on the same Wi-Fi: http://<your-pc-ip>:8000)

Env vars: SECRET_KEY (set a long random value), DATABASE_URL (default sqlite:///./site.db;
PostgreSQL e.g. postgresql://user:pass@host/db).

First person registers with a project name -> becomes Admin. Admin invites by email in the Team tab;
the invitee registers with that same email and joins the project automatically.
Bulk import: CSV with header: date,item,amount,method,paid_to (date as YYYY-MM-DD or DD/MM/YYYY).
