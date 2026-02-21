
import os
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

# 🚀 Database URLs
sqlite_url = "sqlite:///../instance/users.db"
postgres_url = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/mydb"
)

print("🚀 Starting data migration...")

# ⚙️ Create engines
sqlite_engine = create_engine(sqlite_url)
postgres_engine = create_engine(postgres_url)

# 🧩 Reflect metadata
sqlite_meta = MetaData()
sqlite_meta.reflect(bind=sqlite_engine)

postgres_meta = MetaData()
postgres_meta.reflect(bind=postgres_engine)

# 🛠 Create missing tables in PostgreSQL
for table_name, table_obj in sqlite_meta.tables.items():
    if table_name not in postgres_meta.tables:
        print(f"🛠 Creating missing table: {table_name}")
        table_obj.metadata = postgres_meta
        table_obj.create(postgres_engine, checkfirst=True)

# 🧠 Create sessions
SQLiteSession = sessionmaker(bind=sqlite_engine)
sqlite_session = SQLiteSession()

PostgresSession = sessionmaker(bind=postgres_engine)
postgres_session = PostgresSession()

# 📥 Copy data safely
for table_name in sqlite_meta.tables:
    print(f"→ Migrating {table_name}")

    sqlite_table = Table(table_name, sqlite_meta, autoload_with=sqlite_engine)
    postgres_table = Table(table_name, postgres_meta, autoload_with=postgres_engine)

    rows = sqlite_session.execute(sqlite_table.select()).fetchall()
    if not rows:
        continue

    print(f"   Found {len(rows)} rows in {table_name}")

    for row in rows:
        data = dict(row._mapping)
        try:
            with postgres_engine.begin() as conn:
                conn.execute(postgres_table.insert().values(**data))
        except IntegrityError:
            print(f"⚠️ Skipping duplicate row in {table_name}: id={data.get('id')}")
            continue

print("✅ Migration completed successfully!")

# ✅ Close sessions
sqlite_session.close()
postgres_session.close()