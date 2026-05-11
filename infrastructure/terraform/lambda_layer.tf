# ---------------------------------------------------------------------------
# Lambda Layer — shared/scan_events.py
#
# This layer is the authoritative runtime home of scan_events.py.
# Every module Lambda attaches it so it can do a clean top-level import:
#
#   from scan_events import emit_scan_completed
#
# The layer zip is built from shared/ only — no handler code.
# Per-module shim files are kept as development-time convenience so pytest
# can resolve the module without the layer; they are NOT bundled in the
# module zips when source_dir is used.
# ---------------------------------------------------------------------------

data "archive_file" "scan_events_layer_zip" {
  type        = "zip"
  output_path = "${path.module}/../../shared/scan_events_layer.zip"

  # Lambda Python layers must live under python/ inside the zip
  source {
    content  = file("${path.module}/../../shared/scan_events.py")
    filename = "python/scan_events.py"
  }
}

resource "aws_lambda_layer_version" "scan_events" {
  layer_name          = "${var.project}-scan-events"
  description         = "Shared EventBridge emitter — emit_scan_completed()"
  filename            = data.archive_file.scan_events_layer_zip.output_path
  source_code_hash    = data.archive_file.scan_events_layer_zip.output_base64sha256
  compatible_runtimes = ["python3.11"]

  lifecycle {
    create_before_destroy = true
  }
}
