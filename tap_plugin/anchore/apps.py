"""TAP Anchore plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The collector registers in ``ready()`` (req-anchore-client).
"""

from tap_plugins.base import TapPluginConfig


class AnchoreConfig(TapPluginConfig):
    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models/edges.
        super().ready()

        # Inside ready(), not at module top, so loading the app stays light.
        from tap_cares.registry import register_collector

        from tap_plugin.anchore.collectors.anchore_collector.collector import AnchoreCollector

        register_collector(
            key="anchore",
            cls=AnchoreCollector,
            scope="anchore",
            name="Anchore",
            description="Reads vulnerability findings from every configured Anchore Enterprise instance and holds them as Anchore returns them. GET requests only.",
        )
