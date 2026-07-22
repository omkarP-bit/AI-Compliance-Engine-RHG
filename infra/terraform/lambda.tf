variable "environment" {
  type    = string
  default = "dev"
}

variable "image_tag" {
  type    = string
  default = "latest"
}

variable "database_url" {
  type    = string
  default = ""
}

variable "redis_url" {
  type    = string
  default = ""
}

variable "anthropic_api_key" {
  type    = string
  default = ""
}

variable "slack_webhook_url" {
  type    = string
  default = ""
}

variable "private_subnet_ids" {
  type    = list(string)
  default = []
}

resource "aws_iam_role" "ace_lambda" {
  name = "ace-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_lambda_function" "ace_scan" {
  function_name = "ace-scan-${var.environment}"
  role          = aws_iam_role.ace_lambda.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.ace.repository_url}:${var.image_tag}"
  timeout       = 60
  memory_size   = 512

  environment {
    variables = {
      OPA_URL             = "http://localhost:8181"
      DATABASE_URL        = var.database_url
      REDIS_URL           = var.redis_url
      SQS_ALERT_QUEUE_URL = aws_sqs_queue.ace_alerts.url
    }
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.ace_lambda.id]
  }
}

resource "aws_lambda_function" "alert_dispatcher" {
  function_name = "ace-alert-dispatcher-${var.environment}"
  role          = aws_iam_role.ace_lambda.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.ace.repository_url}:alert-${var.image_tag}"
  timeout       = 30
  memory_size   = 256

  environment {
    variables = {
      SLACK_WEBHOOK_URL   = var.slack_webhook_url
      SQS_ALERT_QUEUE_URL = aws_sqs_queue.ace_alerts.url
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs_to_alert" {
  event_source_arn = aws_sqs_queue.ace_alerts.arn
  function_name    = aws_lambda_function.alert_dispatcher.arn
  batch_size       = 10
}

resource "aws_apigatewayv2_api" "ace" {
  name          = "ace-api-${var.environment}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "ace_scan" {
  api_id             = aws_apigatewayv2_api.ace.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.ace_scan.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scan" {
  api_id    = aws_apigatewayv2_api.ace.id
  route_key = "POST /ace/scan"
  target    = "integrations/${aws_apigatewayv2_integration.ace_scan.id}"
}

resource "aws_sqs_queue" "ace_alerts" {
  name                        = "ace-alerts-${var.environment}.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  message_retention_seconds   = 86400
  visibility_timeout_seconds  = 60
}

resource "aws_security_group" "ace_lambda" {
  name        = "ace-lambda-${var.environment}"
  description = "Security group for ACE Lambda functions"
}

resource "aws_ecr_repository" "ace" {
  name = "ace-rhg-${var.environment}"
}
