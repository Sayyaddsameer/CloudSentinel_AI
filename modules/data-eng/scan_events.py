# scan_events.py — data-eng module marker (DO NOT add executable code here)
#
# At RUNTIME (Lambda): scan_events is provided by the shared Lambda Layer at
#   /opt/python/scan_events.py  (aws_lambda_layer_version.scan_events in lambda_layer.tf)
#
# In LOCAL TESTS: shared/ is prepended to sys.path by conftest.py, so
#   `from scan_events import emit_scan_completed` resolves directly to
#   shared/scan_events.py — this file is never executed.
#
# DO NOT place any import or executable code in this file.
