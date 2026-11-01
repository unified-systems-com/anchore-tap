# Test-collection marker (NOT the plugin package).
#
# The plugin's importable code is the installed PEP 420 namespace package
# tap_plugin.anchore (see tap_plugin/anchore/). This file exists only so pytest names this
# project dir's tests fully-qualified, avoiding the orphan-`tests`-package collision when
# two package-mode plugins both expose a bare top-level `tests` package. It ships in NO
# wheel (only tap_plugin/anchore/ is packaged). Deliberately empty otherwise.
