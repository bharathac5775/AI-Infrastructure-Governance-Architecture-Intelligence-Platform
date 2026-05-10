# my-chart

Sample Helm chart for testing the AI Infrastructure Governance Platform.

## Package and test

```bash
# From samples/ directory
helm package my-chart/
# produces: my-chart-1.0.0.tgz

# Preview what gets rendered before uploading
helm template release my-chart-1.0.0.tgz
```

## Intentional issues (for analysis testing)

- `DB_PASSWORD: "supersecret123"` in values.yaml — hardcoded credential in env var
- No `securityContext` on the pod or container — runs as root
- No `livenessProbe` / `readinessProbe` — no health checks
- `ingress.tls: false` — HTTP only, no TLS
- `autoscaling.enabled: false` — no HPA
- Only 2 replicas — low availability
