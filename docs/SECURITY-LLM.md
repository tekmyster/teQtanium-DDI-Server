# Optional model assistance

teQtanium connects to an independently operated model server through the widely implemented OpenAI-compatible Chat Completions HTTP interface. This is a compatibility interface, not a claim of a formally standardized protocol. No vendor SDK or model subscription is required by teQtanium. The model server handles CPU/GPU selection and model loading; teQtanium does not provision a GPU or install model weights.

## Connect a model

1. Run a model server that supports `/v1/chat/completions`, such as [Ollama](https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx) or [vLLM](https://docs.vllm.ai/en/stable/serving/online_serving/openai_compatible_server/). Choose a model that fits the server's available memory.
2. In Security > Protection settings > Model assistance, enter the complete endpoint and the exact served model name. A same-host example is `http://127.0.0.1:11434/v1/chat/completions`. HTTP requires a literal loopback address; a separate GPU server requires HTTPS and Allow a network endpoint. DNS names such as localhost do not qualify for insecure loopback access.
3. If the server requires authentication, set a `DDI_LLM_*_API_KEY` environment variable on the teQtanium service and enter its name under Credential reference. The policy stores only that reference, never the key. Configure credentials on each node that will request analysis. Configuring a reference does not set an environment variable.
4. Enable event explanations and save. An administrator can choose View evidence > Explain event for a recent event. Model analysis is on demand; there is no automatic telemetry upload.

Before saving, choose **Test connection**. It sends a fixed benign question through this node using the entered endpoint, model and credential reference, without event data or policy changes. A reply confirms that transport, authentication and a textual model response worked at that time; it does not enable event explanations. Cancel test stops waiting for the request; a provider may already have begun processing it.

For a private HTTPS CA, provision a PEM CA bundle outside the configuration backup and set `DDI_LLM_CA_FILE` in the service environment on each requesting node. Restart the service during an approved release to load it. This optional trust bundle applies only to model connections and retains certificate hostname, expiry and chain validation. Without it, the platform trust store is used. Missing, unreadable or invalid bundles make model requests unavailable and do not prevent DNS/DHCP startup. Credentials remain referenced by `DDI_LLM_*_API_KEY`; neither keys nor CA file contents are returned by the connection check.

By default, requests omit full query names, domains, client addresses, MAC addresses, DHCP client identifiers, hostnames, site names and raw threat-source evidence. They include selected detector features and scores, sample/coverage metadata, protocol outcome and whether DHCP attribution exists. Include registered domains is an explicit opt-in and still omits full query names. Requests go to the configured endpoint; Allow a network endpoint authorizes that destination, including a separate LAN model server.

## Operation

The connector sends a non-streaming request with `model`, system/user messages and `max_tokens: 600`. It accepts a textual `choices[0].message.content` response. Custom API prefixes and tool-call-only responses are unsupported. There is no tool execution, policy mutation or DNS/DHCP hook in the connector. Endpoint redirects and system proxies are disabled. HTTPS certificate validation remains enabled.

At most two analyses run concurrently per server. Requests are limited to 32 KiB, responses to 64 KiB and 16000 text characters, and each call to 30 seconds. No automatic retry repeats a possibly billable request. Keys are read only from permitted environment references and sent only in a Bearer header. Endpoint credentials, query strings and fragments are rejected. The API requires Settings view and Administration modify permission; changing or rolling back connection settings requires Administration modify in addition to policy modify permission. Successful analysis requests are logged by actor and event reference; model results are not persisted in the investigation store in this increment.

Connection settings travel with security policy backup and synchronization; model credentials and model weights do not. The source and destination must be reviewed during a deployment migration. An explanation uses the current connection settings and a recent node-local event; archived-only events cannot yet be analyzed.

## Dashboard telemetry

Dashboard > Operations on this node shows model requests made by this process. The selected 15-minute or 60-minute window is separate from the existing DNS chart window/node selector. DHCP/IPAM/protection cards are current snapshots, not window totals. No cluster aggregation is performed.

Token counts come only from the provider's `usage.prompt_tokens`, `usage.completion_tokens` and `usage.total_tokens`. All three must be nonnegative exact integers and total must equal input plus output. Missing usage, malformed/negative/overflow counts, and inconsistent totals are counted separately and do not become zero. Explicit reported zero is supported. Canceled or timed-out work may consume provider tokens that were never returned; no estimates, pricing, GPU-wide usage or savings are inferred.

Requests are counted once in the connector. Outcome categories partition completed connector attempts into successful, failed, canceled, timed out, or busy (local capacity rejection or provider HTTP 429). Validation rejected before entering the connector is excluded. In-flight requests are shown separately, with capacity two. Successful-call p50/p95 latency uses monotonic elapsed time, includes connection setup/response reading, and uses nearest rank over the retained window sample; sample count is disclosed. Charts show counts in sliding 60-second bins, not extrapolated rates. Pre-start and retention gaps are unavailable, not zero.

All telemetry is process-local memory. Since-restart totals are retained for the life of this connector; rolling data keeps at most 4096 completions for 60 minutes. Window coverage is marked partial when capacity eviction affects it. Totals saturate at the JavaScript exact integer limit and disclose lower bounds if reached. No persistence or reset endpoint is added. A new process starts with empty counters and observations. At most 32 recent connection identities are retained internally; identity hashes, endpoint addresses, credential references, prompts, responses and event details are never returned in the metrics API.

The configured connection and observed response are separate. A successful unsaved connection test does not enable model assistance or prove that a different saved connection works. Last observation is historical, never a continuous availability probe. IPAM last change is not source freshness. DHCP active leases count unexpired leases stored on this node and do not measure allocatable capacity or exhaustion. MISP status is read-only existing health; no protection effectiveness or EDL qualification follows from this dashboard.

`GET /api/dashboard/operations/get?minutes=15` (or `60`) requires Dashboard view. Model/IPAM/protection aggregates additionally require Settings view; DHCP requires DHCP view. Unpermitted sections are null and rendered as restricted. Administration modify remains required to send a model connection test. Metrics responses are not cached. No statistics collection runs in resolver or DHCP request hooks, and no disk writes are added.

Run `dotnet run --project tests/Ipam.Tests/Ipam.Tests.csproj -c Release -- --llm-metrics` for benign telemetry fixtures, independent of analytics/MISP/EDL suites.

## Validation

Run `dotnet run --project tests/Ipam.Tests/Ipam.Tests.csproj -c Release -- --llm` for benign connector-only fixtures. This entry point does not run detector, exfiltration, MISP or EDL checks and does not call an external model.

Synthetic detector regressions, mocked provider request/response tests and native API permission tests exercise this implementation. They do not establish accuracy, a live Ollama/vLLM connection, GPU compatibility, GPU capacity or any hosted model's privacy/retention behavior. No production provider is configured or called during those tests. Trained classifiers and predictive intelligence are separate delivery items in [the roadmap](SECURITY-ROADMAP.md).

### Historical local verification on 2026-10-13

The Release application/test builds passed. The complete DDI regression run passed 401 checks, including 76 authenticated API checks and an end-to-end HTTP request to an isolated loopback model fixture. An additional invalid-credential-header case brought the focused analytics/connector run to 31 passing checks; that focused suite and presentation checks were rerun after the final connector change.

Desktop event evidence, a successful advisory explanation and the 390-pixel model settings view were visually inspected. The checked page had no horizontal overflow, all six new controls had labels, raw event data remained collapsed and provider HTML-like text was displayed literally. Additional observation windows are disclosed separately. Provider failures were tested through code; browser loading, provider-error and reader-role states were not all visually exercised. The screenshots and receipts for that historical fixture pass remain private. Production services and security settings were not changed by that pass. Later scoped operation is described below.

### Scoped current operation — 21 October 2026, 12:34 EDT

Independent review accepted measured connection tests, administrative/usage results, both bridge sources, served assets, sampled live DNS and exact-version disposable checks. This is scoped acceptance, not full LLM activation. A connection test is not an existing-event explanation. Required real-event explanation, actual production outbound privacy, current loaded binary/references, fresh node-source administrative access and DHCP packet/lease isolation remain unverified.

Disposable native event API checks captured redacted outbound fixture bodies and exercised permissions; they do not prove production wire privacy or diagnosis accuracy. During a stalled fixture provider, the same application answered DNS with REFUSED; separate successful live DNS samples are not successful resolution during that outage. Current live screenshots/assets and interactive disposable reader/expired-session checks cover specific states; omitted loading/error/race states and broader runtime paths require their own checks. See [dated delivery status](DEPLOYMENT-STATUS.md).
