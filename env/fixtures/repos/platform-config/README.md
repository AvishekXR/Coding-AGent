# platform-config

Shared Kubernetes ConfigMaps for every service, per environment overlay.

Changes here are applied to the cluster by the config sync job. **They affect running
services in other teams' repositories** -- a key rename is a breaking API change for every
consumer that reads it. Consumers are not listed here; use the reverse index.

**On-call:** #platform-oncall
