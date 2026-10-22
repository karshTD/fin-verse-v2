$env:FINSECURE_S3_BUCKET = "finsecure-docs-sitp-2026"
$env:AWS_REGION = "ap-southeast-2"
# Replace with a long random value before use. Keep this file out of public repositories.
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret-before-running"
python app.py
