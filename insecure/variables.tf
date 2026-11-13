variable "project_id" {
  description = "Google Cloud project ID to deploy into (use a throwaway lab project)"
  type        = string
}

variable "region" {
  description = "Region for regional resources"
  type        = string
  default     = "europe-west3" # Frankfurt
}

variable "zone" {
  description = "Zone for the VM"
  type        = string
  default     = "europe-west3-a"
}
