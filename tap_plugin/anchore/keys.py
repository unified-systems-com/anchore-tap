"""The key field names of types this plugin writes but does not own, read from the type itself.

computing_core and aws_core own their types and may rename a key entry: a host's issuer is the
dimension ``tap.computing.host_type`` (tap#1355), and an aws_core type's ``<kind>_arn`` is to
become ``arn``. A name
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


def is_dimension(entry: str) -> bool:
    """Whether a key entry names a dimension (``dimension:<name>``) rather than a field.

    Core's own test where the installed grid has it; an older grid has no dimension entries.
    """
    try:
        from tap_grid.natural_key import is_dimension as core_is_dimension
    except ImportError:
        return False
    return bool(core_is_dimension(entry))


def dimension_name(entry: str) -> str:
    """The dimension a dimension entry names."""
    from tap_grid.natural_key import dimension_name as core_dimension_name

    return str(core_dimension_name(entry))


def scheme_field(model: Any) -> str:
    """The entry beside ``stable_id`` in a two-part key: the one that names who issued the identifier.

    A field name, or a dimension entry (``dimension:tap.computing.host_type``) where the type keys
    on a dimension. Either is how a key
    reference (``from_key``, ``to_key``) spells it; :func:`split` says where it goes in a node.
    """
    key = _natural_key(model)
    others = [name for name in key if name != STABLE_ID]
    if STABLE_ID not in key or len(others) != 1:
        raise KeyShapeError(f"{model.ENTITY_TYPE} is keyed {key!r}; expected stable_id and one field naming its issuer")
    return others[0]


def split(model: Any, values: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Key values as a node carries them: ``(fields, dimensions)``.

    A field entry stays in the node's fields; a dimension entry goes to the node's dimensions, under
    the dimension's name, since a dimension is never part of a node's payload. Values that are not
    key entries are fields.
    """
    fields: dict[str, Any] = {}
    dimensions: dict[str, Any] = {}
    for name, value in values.items():
        if is_dimension(name):
            dimensions[dimension_name(name)] = value
        else:
            fields[name] = value
    return fields, dimensions


def spine_key(model: Any, values: Any, dimensions: Any = None) -> str | None:
    """A node's natural key as the grid stores it; None when it cannot be composed.

    ``values`` is a key reference (``{entry: value}``) or a node's fields; ``dimensions`` is the
    node's dimension map, read for a dimension entry a key reference does not carry. The grid's own
    functions read and compose, so the string is the one the grid writes for the node and never a
    second recipe. None when an entry is missing or null, for a JSON-path entry, and when the
    installed grid is older than those functions.
    """
    try:
        from tap_grid.natural_key import compose_natural_key, is_path, normalized_key_values
    except ImportError:
        return None
    declared = _natural_key(model)
    properties: dict[str, Any] = {}
    for name in declared:
        if is_dimension(name):
            value = values.get(name)
            if value is None and dimensions:
                value = dimensions.get(dimension_name(name))
            properties[name] = value
        elif is_path(name):
            return None
        else:
            properties[name] = values.get(name)
    return compose_natural_key(model, normalized_key_values(model, properties))


def sole_field(model: Any) -> str:
    """The one field of a single-field key, such as the ARN of an aws_core type."""
    key = _natural_key(model)
    if len(key) != 1:
        raise KeyShapeError(f"{model.ENTITY_TYPE} is keyed {key!r}; expected one field")
    return key[0]
