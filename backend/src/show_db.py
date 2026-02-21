
# show_db.py
from importlib import import_module
# adjust if your top-level package path differs
app_module = import_module("backend.src.app")
app = getattr(app_module, "app")
print("app.config['SQLALCHEMY_DATABASE_URI']:", app.config.get("SQLALCHEMY_DATABASE_URI"))
