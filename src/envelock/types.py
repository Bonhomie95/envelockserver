"""Native Postgres column types. Postgres is the only supported backend."""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

#: A list of strings, stored as a native Postgres text array.
StringList = ARRAY(String)

#: A JSON object, stored as JSONB (binary, indexable).
JsonDict = JSONB
