# DEX default product UX contract

Act as a senior product designer, UX writer and software engineer. Build production-quality applications that feel deliberately designed. Prioritize clarity, polish, consistent terminology and correctness across the whole project.

## Interface copy

Use concise, precise, action-oriented language familiar to DNS, DHCP, IPAM and security operators. Prefer short labels without sacrificing clarity. Do not expose internal variable names or API jargon as labels. Add help only when it supports a decision or resolves ambiguity. Retain meaningful safety, privacy, security and destructive-action warnings at the relevant step; avoid generic disclaimers and repetitive caution.

## Information architecture

Show essential information and the primary action first. Use progressive disclosure for advanced settings, diagnostics and secondary actions. Present structured readable evidence rather than JSON, stack traces or configuration objects. Raw data belongs only in an explicitly labeled developer view. Preserve information needed for informed decisions and existing functionality.

## Terminology and feedback

Use the same term for the same concept across screens. Describe fields and actions by operator intent. Keep identifiers, enum values and API keys unchanged behind presentation mappings. Make validation specific and actionable. Explain errors in human terms with a next step; keep diagnostics available separately. Design loading, empty, success, disabled and failure states. Confirm success only after the relevant outcome is acknowledged.

## Visual and interaction design

Follow the existing Bootstrap components, themes and teQtanium brand. Maintain clear hierarchy, disciplined spacing, consistent typography and aligned controls. Avoid decorative clutter or invented visual conventions. Support narrow layouts, accessible contrast, meaningful labels, keyboard interaction and intentional focus. Each screen needs a clear purpose and obvious primary action.

## Engineering boundaries

Separate service data from presentation models. Do not replace UI design with object dumps. Preserve business logic, integration behavior, validation and data contracts unless the requested change requires otherwise. Avoid unrelated rewrites. Do not fabricate APIs, behavior, dependencies or test outcomes. When communicating code, provide complete changed sections without unrelated file dumps.

## Mandatory quality gate

Before declaring a UI implementation complete, inspect affected screens and fix:

1. Unnecessary, repetitive or artificial-sounding explanations.
2. Generic disclaimers, misplaced warnings or warning overload.
3. Raw JSON, object dumps, stack traces or developer jargon in ordinary views.
4. Ambiguous, inconsistent or overly technical labels.
5. Weak hierarchy, clutter or inconsistent spacing.
6. Inconsistent components, terminology, patterns or states.
7. Missing responsive behavior, accessibility, loading, empty or error handling.
8. Regressions in functionality, contracts, validation or required disclosures.

Report any screens, states or paths that could not be inspected or executed. Keep summaries concise, focused on changes and material unresolved issues, and distinguish verified behavior from assumptions.

Current feature-specific acceptance and omitted states are recorded in [dated status](DEPLOYMENT-STATUS.md). A historical full-section inspection does not cover every state introduced by subsequent changes.

The end user should experience a polished product, not the technical process used to generate it. Optimize for simplicity without sacrificing correctness, safety, accessibility or function.

## Implementation and historical verification scopes

The contract applies through root `AGENTS.md`. `DnsServerCore/www/js/product-ux.js` centralizes readable values, DNS record views, accessible dynamic controls, table scrolling, unclipped action menus, dialog naming and focus. The console shell and dialogs adapt to narrow widths. Main, dark and amber styles preserve the existing components while improving text contrast; dashboard chart labels follow the theme.

Security leads with recent events, presents structured indicator/device/score evidence, and keeps raw events under Developer data. Investigations select events by time and domain, while an advanced event-reference option retains external-reference entry. IPAM leads with inventory; editing, history and NetBox configuration use disclosure. DNS tools, cache and filtering record views show structured records with optional developer data. Unsupported record fields remain available in that developer view. Third-party application configuration retains its original editor under Developer configuration rather than inventing unknown application schemas. The public DNS setup page uses concise instructions.

Historical verification for the original UX pass (not a new run or current deployment acceptance):

- All 14 main sections were inspected: Dashboard, Zones, Cache, Allowed, Blocked, Apps, DNS Client, Settings, DHCP, IPAM, Security, Administration, Logs and About.
- The primary sections, all nine Settings tabs and seven Administration tabs were checked at a 390-pixel viewport for page overflow and accessible form labels. The checked views had no page-level horizontal overflow or unnamed visible form inputs.
- Desktop screenshots, the narrow Add Zone dialog, zone-action dropdowns and the public DNS setup page were inspected. The zone dialog fits the viewport and focuses its Zone field; menus remain usable outside scrolling tables.
- Real DNS-tool requests reached the local resolver and rendered its security REFUSED response as structured results. Existing security events rendered as readable evidence. No claim of successful resolution is made for that intentionally blocked query.
- All 1,233 existing DOM identifiers were preserved. The shared module is copied into the Release application output. Shared request outcome, authentication-header, error escaping, readable DNS-value and HTML/syntax checks run through `node scripts/test-product-ux.mjs` and the DDI test script; Node.js is required for that presentation test.
- The existing 311 DDI checks passed. Production access controls and credentials were not changed. Existing isolated access tests retain original sessions through fresh authentication and privilege checks on loopback; other source paths remain untested.

This verification does not exercise every record subtype, destructive operation, authentication provider, configured external integration or third-party application's settings. Those workflows keep their existing validation and permissions and require their own deployment-specific execution checks. Continue the mandatory quality gate as features change.

Backup/migration verification: readable backup choices, a named New Deployment dialog, package preview and desktop/390-pixel layouts were inspected. Browser import confirmed success feedback, refreshed settings and disabled replay controls; initial focus moves to the package input. ZIP responses and rollback are tested through native API fixtures. Browser Blob-download filesystem completion was not observable through the in-app automation event.

teQtanium branding verification: the console shell, sign-in, About, desktop Dashboard/Security/DHCP and all 14 main section first views at 390 pixels were inspected. None of those mobile views had page-level horizontal overflow. The public DNS setup page was inspected through a local static server; its live encrypted DNS endpoint was not retested. Shared presentation checks and the Linux publish passed. Existing preferences remain available; new browsers default to dark grey. Every dialog, subtab and alternate theme state was not re-exercised in this branding pass. Original SVG/1024-pixel PNG and light/transparent variants are preserved in `docs/branding`.
