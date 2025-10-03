# Alembic Migrations

This folder contains Alembic migration scripts for your database schema.

- To generate a new migration after model changes:

```bash
alembic revision --autogenerate -m "Describe your change"
```

- To apply migrations to your database:

```bash
alembic upgrade head
```

- Make sure your `env.py` is configured to import your SQLAlchemy `Base` and database URL.
