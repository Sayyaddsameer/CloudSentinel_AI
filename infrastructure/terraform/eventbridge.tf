# EventBridge — schedule ai-explainer to run every hour automatically

resource "aws_cloudwatch_event_rule" "ai_explainer_schedule" {
  name                = "${var.project}-ai-explainer-hourly"
  description         = "Runs the AI explainer Lambda every hour so new risks get explanations automatically"
  schedule_expression = "rate(1 hour)"
  tags                = { Project = var.project }
}

resource "aws_cloudwatch_event_target" "ai_explainer_target" {
  rule      = aws_cloudwatch_event_rule.ai_explainer_schedule.name
  target_id = "AIExplainerLambda"
  arn       = aws_lambda_function.ai_explainer.arn
}
