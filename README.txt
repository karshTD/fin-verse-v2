FinSecure local academic demo

Setup (Windows PowerShell):
1. Install dependencies once: python -m pip install -r requirements.txt
2. Ensure AWS CLI credentials work: aws sts get-caller-identity
3. Set environment variables in the terminal:
   $env:FINSECURE_S3_BUCKET="finsecure-docs-sitp-2026"
   $env:AWS_REGION="ap-southeast-2"
   $env:FLASK_SECRET_KEY="use-a-long-random-secret-value"
4. Start the app: python app.py
5. Open http://127.0.0.1:5000/

Seeded demo accounts (initial password for each: FinSecure123):
admin@finsecure.com - Administrator
accountant1@finsecure.com - Accountant, Client A
accountant2@finsecure.com - Accountant, Client B
auditor1@finsecure.com - Auditor, Client A and Client B

User records are stored in finsecure.db, a local SQLite database. Passwords are stored using Werkzeug password hashes. The admin can create additional accounts in Users & Access; new passwords must be at least 12 characters.

Important: this remains an academic demo. Seeded accounts share an initial password; change them before any wider use. The user-management feature creates users but does not yet provide edit/deactivate/reset workflows. Do not use real financial records. Do not expose Flask debug server to the internet.

S3 bucket must remain private. IAM identity needs list/get/put permissions for documents/* as appropriate.
