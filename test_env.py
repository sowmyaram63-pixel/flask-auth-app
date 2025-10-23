import os
from dotenv import load_dotenv

load_dotenv(dotenv_path='myproject/.env')

print("GOOGLE_CLIENT_ID:", os.getenv("GOOGLE_CLIENT_ID"))
print("GOOGLE_CLIENT_SECRET:", os.getenv("GOOGLE_CLIENT_SECRET"))

