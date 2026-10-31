# Observability

Two backends, one metric vocabulary.

| | Local (`ACE_PROFILE=local`) | Cloud (`ACE_PROFILE=cloud`) |
|---|---|---|
| Collection | Prometheus scrapes `ace:9090` / `rhg:9091` | Lambda prints CloudWatch EMF to stdout |
| Storage | Prometheus TSDB | CloudWatch metrics (`ACE-RHG` namespace) |
| UI | Grafana `http://localhost:3000` | CloudWatch dashboard / Grafana Cloud |

The metric names are identical in both backends:

| Metric | Dimensions | Unit |
|---|---|---|
| `ace_scans_total` | `environment`, `outcome` | Count |
| `ace_findings_total` | `severity`, `rule_id` | Count |
| `ace_mutations_total` | `outcome` | Count |
| `rhg_gate_decisions_total` | `decision`, `environment` | Count |
| `ace_scan_duration_seconds` | — | Seconds |
| `ace_agent_duration_seconds` | `agent_name` | Seconds |
| `ace_active_scans` | — | None |
| `ace_opa_health` | — | None (1 = up) |
| `ace_compliance_score` | `environment` | None (0–10) |

## Local stack

```bash
docker compose up -d prometheus grafana
open http://localhost:3000        # admin / admin
```

The provisioned dashboard is `ACE+RHG — Release Hardening Overview`
(`http://localhost:3000/d/ace-rhg-overview`).

## Cloud: CloudWatch EMF

Lambda has no scrapeable port, so `ace.metrics.cloudwatch.CloudWatchMetrics`
emits one Embedded Metric Format JSON document per sample. CloudWatch Logs
extracts the values into the `ACE-RHG` namespace. No `cloudwatch:PutMetricData`
permission is required — the metrics ride on the existing log stream.

Environment variables (set on both `ace-scan-dev` and `ace-rhg-dev`):

| Variable | Default | Purpose |
|---|---|---|
| `CLOUDWATCH_NAMESPACE` | `ACE-RHG` | CloudWatch namespace |
| `CLOUDWATCH_EMF_ENABLED` | `true` in Lambda, `false` elsewhere | Kill switch |
| `METRICS_BACKEND` | auto (`cloudwatch` in Lambda, else `prometheus`) | Explicit backend override |
| `DASHBOARD_URL` | `http://localhost:3000/d/ace-rhg-overview` | Full dashboard URL used in alerts |

`DASHBOARD_URL` is used verbatim (no path is appended), so it can point at
Grafana, Grafana Cloud or a CloudWatch dashboard.

### Native CloudWatch dashboard

```bash
aws cloudwatch put-dashboard \
  --region ap-south-1 \
  --dashboard-name ACE-RHG-Overview \
  --dashboard-body file://infra/observability/cloudwatch/ace-rhg-overview.json
```

Then open **CloudWatch → Dashboards → ACE-RHG-Overview**:

```
https://ap-south-1.console.aws.amazon.com/cloudwatch/home?region=ap-south-1#dashboards:name=ACE-RHG-Overview
```

### Grafana Cloud

1. Create a free Grafana Cloud stack (or use an existing one).
2. Create an IAM user with read-only CloudWatch access:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "cloudwatch:ListMetrics",
           "cloudwatch:GetMetricData",
           "cloudwatch:GetMetricStatistics",
           "cloudwatch:DescribeAlarms"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   Create an access key for that user.
3. In Grafana: **Connections → Data sources → Add → CloudWatch**
   - Region: `ap-south-1`
   - Auth provider: Access & secret key (the key from step 2)
4. Import `infra/observability/grafana/cloud/ace-rhg-cloudwatch.json`
   and pick the CloudWatch data source when prompted.
5. Point alerts at the imported dashboard:

   ```bash
   aws lambda update-function-configuration \
     --region ap-south-1 \
     --function-name ace-rhg-dev \
     --environment "Variables={...,DASHBOARD_URL=https://<stack>.grafana.net/d/ace-rhg-cloudwatch}"
   ```

   Repeat for `ace-scan-dev`.

### Amazon Managed Grafana

Amazon Managed Grafana requires an IAM Identity Center (SSO) instance. This
account/region does not have one, so the workspace cannot be created until SSO
is configured. Grafana Cloud is the drop-in alternative above.

## Caveats

- Lambda metrics are **per container**. `ace_scans_total` and
  `ace_findings_total` are counters that reset on cold start; CloudWatch
  treats each emission as a sample, so use `Sum` over a window rather than
  expecting a monotonic counter.
- `ace_active_scans` is only meaningful per container and will normally read
  `0` between invocations.
- The in-process OPA health probe does not run in Lambda (Lifespan is off);
  `ace_opa_health` is emitted on each `/ace/scan` call instead.
- CloudWatch EMF is not a replacement for tracing. Agent-level latency is a
  p95 per node, not a trace.
