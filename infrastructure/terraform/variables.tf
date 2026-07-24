variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "Target AWS Region"
}

variable "environment" {
  type        = string
  default     = "dev"
  description = "Deployment environment"
}

variable "db_username" {
  type        = string
  sensitive   = true
  description = "Database admin username passed at runtime"
}

variable "db_password" {
  type        = string
  sensitive   = true
  description = "Database admin password passed via environment or secret manager"
}
