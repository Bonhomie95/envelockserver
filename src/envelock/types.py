"""Portable column types so the same models run on Postgres and SQLite."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import JSON, String, Text, TypeDecorator
from sqlalchemy.dialects.postgresql import ARRAY, JSONB


class StringList(TypeDecorator):
    """`ARRAY(String)` on Postgres, JSON-encoded text on SQLite."""

    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):  # noqa: ANN001, ANN201
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(String))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value: Any, dialect) -> Any:  # noqa: ANN001
        if value is None:
            return None
        if dialect.name == "postgresql":
            return list(value)
        return json.dumps(list(value))

    def process_result_value(self, value: Any, dialect) -> Any:  # noqa: ANN001
        if value is None:
            return []
        if dialect.name == "postgresql":
            return list(value)
        return json.loads(value)


class JsonDict(TypeDecorator):
    """`JSONB` on Postgres, `JSON` elsewhere."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):  # noqa: ANN001, ANN201
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
