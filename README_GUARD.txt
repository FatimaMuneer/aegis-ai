GUARD PACK (Person A)
=====================
Unzip this INTO your aegis-project folder (the one that contains aegis, tests, scripts and venv).
Say YES / "Replace" if asked. It adds these files and does not touch models.py:

  aegis/policy.py
  aegis/db_guard.py        aegis/policies/database.yaml     tests/test_db_guard.py
  aegis/ops_guard.py       aegis/policies/devops.yaml       tests/test_ops_guard.py
  aegis/soc_guard.py       aegis/policies/soc.yaml          tests/test_soc_guard.py
  scripts/try_guard.py

Then, in the VS Code terminal (with (venv) showing):

  python -m pytest tests/test_db_guard.py tests/test_ops_guard.py tests/test_soc_guard.py

Expected: all tests pass (62 passed).

Try your own actions:
  python scripts/try_guard.py sql "DROP TABLE orders"
