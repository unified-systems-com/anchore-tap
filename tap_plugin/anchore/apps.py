"""TAP Anchore plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The collector registers in ``ready()`` when it is built (req-anchore-client and the scope walk).
"""

from tap_plugins.base import TapPluginConfig


class AnchoreConfig(TapPluginConfig):
    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models/edges.
        super().ready()
