"""The key field names of types this plugin writes but does not own, read from the type itself.

computing_core and aws_core own their types and may rename a key field: a host's ``realm`` is to
become ``host_id_scheme``, and an aws_core type's ``<kind>_arn`` is to become ``arn``. A name
written out here would break every write and every lookup on the day of the rename, in a release
already installed. So the name is taken from the model's ``NATURAL_KEY`` at run time, by the role
the field plays and not by its position, and a key of a shape this plugin does not understand is
refused loudly instead of guessed at (req-anchore-shared-13).
"""

from typing import Any

STABLE_ID = "stable_id"


class KeyShapeError(RuntimeError):
    """A type's natural key is not of the shape this plugin writes."""


def _natural_key(model: Any) -> tuple[str, ...]:
    key = getattr(model, "NATURAL_KEY", None)
    if not isinstance(key, tuple) or not all(isinstance(name, str) for name in key):
        raise KeyShapeError(f"{getattr(model, 'ENTITY_TYPE', model)!s} declares no natural key of field names")
    return key


def scheme_field(model: Any) -> str:
    """The field beside ``stable_id`` in a two-part key: the one that names who issued the identifier."""
    key = _natural_key(model)
    others = [name for name in key if name != STABLE_ID]
    if STABLE_ID not in key or len(others) != 1:
        raise KeyShapeError(f"{model.ENTITY_TYPE} is keyed {key!r}; expected stable_id and one field naming its issuer")
    return others[0]


def spine_key(model: Any, values: Any) -> str | None:
    """A node's natural key as the grid stores it, from field values; None when it cannot be composed.

    The grid's own function does the composing, so the string is the one the grid writes for the
    node and never a second recipe. None when a key field is missing or null, and when the
    installed grid is older than that function.
    """
    try:
        from tap_grid.natural_key import compose_natural_key
    except ImportError:
        return None
    declared = _natural_key(model)
    if any("." in name for name in declared):
        return None
    return compose_natural_key(model, {name: values.get(name) for name in declared})


def sole_field(model: Any) -> str:
    """The one field of a single-field key, such as the ARN of an aws_core type."""
    key = _natural_key(model)
    if len(key) != 1:
        raise KeyShapeError(f"{model.ENTITY_TYPE} is keyed {key!r}; expected one field")
    return key[0]
