# ---------------------------------------------------------------------------
# cors.tf — API Gateway CORS preflight for all routes
#
# Every route sends Authorization header → triggers CORS preflight (OPTIONS).
# Without an OPTIONS handler API Gateway returns 403 and the browser blocks
# the real request entirely ("Failed to fetch").
#
# Pattern per resource:
#   aws_api_gateway_method          OPTIONS / authorization = NONE
#   aws_api_gateway_integration     MOCK (never reaches Lambda)
#   aws_api_gateway_method_response 200 with Access-Control-Allow-* headers
#   aws_api_gateway_integration_response  maps header values
#
# Gateway responses add CORS headers to API GW-level errors (403 auth etc.)
# so the browser sees the real error instead of a network failure.
# ---------------------------------------------------------------------------

locals {
  cors_allow_origin  = "*"
  cors_allow_headers = "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token"
  cors_allow_methods = "GET,POST,OPTIONS"

  cors_resources = {
    risks               = aws_api_gateway_resource.risks.id
    chat                = aws_api_gateway_resource.chat.id
    scan_cloud          = aws_api_gateway_resource.scan_cloud.id
    disconnect          = aws_api_gateway_resource.disconnect.id
    notify              = aws_api_gateway_resource.notify.id
    scan_devops         = aws_api_gateway_resource.scan_devops.id
    scan_fullstack      = aws_api_gateway_resource.scan_fullstack.id
    scan_mobile         = aws_api_gateway_resource.scan_mobile.id
    scan_data_eng       = aws_api_gateway_resource.scan_data_eng.id
    validate_connection = aws_api_gateway_resource.validate_connection.id
  }
}

# ── OPTIONS method (no auth — preflight must be unauthenticated) ──────────
resource "aws_api_gateway_method" "options" {
  for_each      = local.cors_resources
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = each.value
  http_method   = "OPTIONS"
  authorization = "NONE"
}

# ── MOCK integration — returns 200 immediately, never hits Lambda ─────────
resource "aws_api_gateway_integration" "options" {
  for_each          = local.cors_resources
  rest_api_id       = aws_api_gateway_rest_api.api.id
  resource_id       = each.value
  http_method       = aws_api_gateway_method.options[each.key].http_method
  type              = "MOCK"
  request_templates = { "application/json" = "{\"statusCode\": 200}" }
}

# ── Method response — declares which CORS headers the response exposes ────
resource "aws_api_gateway_method_response" "options" {
  for_each    = local.cors_resources
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = each.value
  http_method = aws_api_gateway_method.options[each.key].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
  }

  response_models = { "application/json" = "Empty" }
}

# ── Integration response — sets the actual header values ─────────────────
resource "aws_api_gateway_integration_response" "options" {
  for_each    = local.cors_resources
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = each.value
  http_method = aws_api_gateway_method.options[each.key].http_method
  status_code = aws_api_gateway_method_response.options[each.key].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = "'${local.cors_allow_origin}'"
    "method.response.header.Access-Control-Allow-Headers" = "'${local.cors_allow_headers}'"
    "method.response.header.Access-Control-Allow-Methods" = "'${local.cors_allow_methods}'"
  }

  depends_on = [aws_api_gateway_integration.options]
}

# ── Gateway responses — CORS headers on API GW-level errors ──────────────
resource "aws_api_gateway_gateway_response" "default_4xx" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  response_type = "DEFAULT_4XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'${local.cors_allow_origin}'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'${local.cors_allow_headers}'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'${local.cors_allow_methods}'"
  }
}

resource "aws_api_gateway_gateway_response" "default_5xx" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  response_type = "DEFAULT_5XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'${local.cors_allow_origin}'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'${local.cors_allow_headers}'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'${local.cors_allow_methods}'"
  }
}
