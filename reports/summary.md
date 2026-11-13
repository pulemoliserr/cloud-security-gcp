# Checkov scan: before and after hardening

| | Insecure | Secure |
|---|---:|---:|
| Passed checks | 23 | 74 |
| **Failed checks** | **31** | **0** |
| Skipped (with justification) | 0 | 1 |

## Findings in the insecure configuration

| # | Check | Resource | Finding | Fixed? |
|---|---|---|---|---|
| M1 | `CKV2_PORTFOLIO_1` *(custom)* | `google_compute_network.vpc` | Ensure VPC networks use custom-mode subnets (no auto-created subnets in every region) | Yes |
| M2 | `CKV2_PORTFOLIO_3` *(custom)* | `google_compute_firewall.allow_admin` | Ensure VPC firewall rules have logging enabled | Yes |
| M2 | `CKV_GCP_2` | `google_compute_firewall.allow_admin` | Ensure Google compute firewall ingress does not allow unrestricted ssh access | Yes |
| M2 | `CKV_GCP_3` | `google_compute_firewall.allow_admin` | Ensure Google compute firewall ingress does not allow unrestricted rdp access | Yes |
| M3 | `CKV_GCP_117` | `google_project_iam_member.app_editor` | Ensure basic roles are not used at project level. | Yes |
| M3 | `CKV_GCP_49` | `google_project_iam_member.app_editor` | Ensure roles do not impersonate or manage Service Accounts used at project level | Yes |
| M4 | `CKV2_PORTFOLIO_2` *(custom)* | `google_service_account_key.app_key` | Ensure service account keys are not created (use attached identities or Workload Identity Federation) | Yes |
| M5 | `CKV_GCP_32` | `google_compute_instance.web` | Ensure 'Block Project-wide SSH keys' is enabled for VM instances | Yes |
| M5 | `CKV_GCP_35` | `google_compute_instance.web` | Ensure 'Enable connecting to serial ports' is not enabled for VM Instance | Yes |
| M5 | `CKV_GCP_38` | `google_compute_instance.web` | Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) | Yes |
| M5 | `CKV_GCP_39` | `google_compute_instance.web` | Ensure Compute instances are launched with Shielded VM enabled | Yes |
| M5 | `CKV_GCP_40` | `google_compute_instance.web` | Ensure that Compute instances do not have public IP addresses | Yes |
| M6 | `CKV_GCP_114` | `google_storage_bucket.exports` | Ensure public access prevention is enforced on Cloud Storage bucket | Yes |
| M6 | `CKV_GCP_28` | `google_storage_bucket_iam_member.public_read` | Ensure that Cloud Storage bucket is not anonymously or publicly accessible | Yes |
| M6 | `CKV_GCP_29` | `google_storage_bucket.exports` | Ensure that Cloud Storage buckets have uniform bucket-level access enabled | Yes |
| M6 | `CKV_GCP_62` | `google_storage_bucket.exports` | Bucket should log access | Yes |
| M6 | `CKV_GCP_78` | `google_storage_bucket.exports` | Ensure Cloud storage has versioning enabled | Yes |
| M7 | `CKV2_GCP_13` | `google_sql_database_instance.db` | Ensure PostgreSQL database flag 'log_duration' is set to 'on' | Yes |
| M7 | `CKV_GCP_108` | `google_sql_database_instance.db` | Ensure hostnames are logged for GCP PostgreSQL databases | Yes |
| M7 | `CKV_GCP_109` | `google_sql_database_instance.db` | Ensure the GCP PostgreSQL database log levels are set to ERROR or lower | Yes |
| M7 | `CKV_GCP_11` | `google_sql_database_instance.db` | Ensure that Cloud SQL database Instances are not open to the world | Yes |
| M7 | `CKV_GCP_110` | `google_sql_database_instance.db` | Ensure pgAudit is enabled for your GCP PostgreSQL database | Yes |
| M7 | `CKV_GCP_111` | `google_sql_database_instance.db` | Ensure GCP PostgreSQL logs SQL statements | Yes |
| M7 | `CKV_GCP_14` | `google_sql_database_instance.db` | Ensure all Cloud SQL database instance have backup configuration enabled | Yes |
| M7 | `CKV_GCP_51` | `google_sql_database_instance.db` | Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on' | Yes |
| M7 | `CKV_GCP_52` | `google_sql_database_instance.db` | Ensure PostgreSQL database 'log_connections' flag is set to 'on' | Yes |
| M7 | `CKV_GCP_53` | `google_sql_database_instance.db` | Ensure PostgreSQL database 'log_disconnections' flag is set to 'on' | Yes |
| M7 | `CKV_GCP_54` | `google_sql_database_instance.db` | Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on' | Yes |
| M7 | `CKV_GCP_6` | `google_sql_database_instance.db` | Ensure all Cloud SQL database instance requires all incoming connections to use SSL | Yes |
| M7 | `CKV_GCP_60` | `google_sql_database_instance.db` | Ensure Cloud SQL database does not have public IP | Yes |
| M7 | `CKV_GCP_79` | `google_sql_database_instance.db` | Ensure SQL database is using latest Major version | Yes |

## Failed checks per misconfiguration

| Misconfiguration | Failed checks |
|---|---:|
| M1 | 1 |
| M2 | 3 |
| M3 | 2 |
| M4 | 1 |
| M5 | 5 |
| M6 | 5 |
| M7 | 14 |

## Accepted exceptions in the secure configuration

- `CKV_GCP_62` on `google_storage_bucket.access_logs`: This IS the access-log bucket; logging it into itself would loop

*M8 (no Data Access audit logs) is not detected by any check, because scanners struggle to flag something that is missing. It was found by manual review; see the README.*
