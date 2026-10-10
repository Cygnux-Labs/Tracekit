# HTTP security checklist

Every HTTP surface of Tracekit passes this checklist. Each item names the tests that enforce it;
`tests/test_security_checklist.py` fails when a handler is added without being listed below and probed, or when a test
named here no longer exists.

## Surfaces

| Handler | Serves | Kind |
|---|---|---|
| `tracekit/observe.py:Handler` | `tracekit view` (v2 store) and `tracekit observe` (v0.2 ledger) | browser, read-only |
| `tracekit/transport/http.py:_Handler` | signer `POST /v2/rpc` and OTLP/HTTP `POST /v1/traces`; `tracekit issuer serve` | API |
| `tracekit/gateway.py:_Handler` | `tracekit gateway serve` (LLM gateway) | API |
| `tracekit/signer/metrics.py:Handler` | signer `/metrics`, `/logs/v0` and tlog tiles | API, public data |
| `tracekit/otlp.py:H` | `tracekit otel serve` (loopback OTLP receiver) | API |
| `tracekit/ingest.py:H` | `tracekit ingest serve` (remote ingest) | API |
| `tracekit/witness_server.py:H` | `tracekit witness serve` | API |
| `tracekit/proxy.py:Handler` | `tracekit-proxy` (Anthropic proxy) | API |
| `tracekit/slack_approvals.py:Handler` | `tracekit approvals slack serve` (Slack interactivity callbacks) | API, Slack-signed |

The browser surface is the only one that serves HTML or holds a session. API surfaces authenticate every request by
header or client certificate (bearer token, mTLS, Kubernetes service-account token, run token) and never read a
cookie, so a browser cannot ride a session on them. The Slack bridge authenticates each callback by Slack's v0 request
signature instead, and answers approvals only through the signer as the Slack user who clicked.

## Checklist

| # | Item | Enforced by |
|---|---|---|
| 1 | HTML and attribute sinks: every value interpolated into the page goes through `esc()` (`& < > " '`) | `tests/test_observe_render.py::EscapingStaticCheck::test_terminal_html_escapes_every_interpolation`, `tests/test_view.py::View::test_hostile_tool_names_are_data_and_the_page_escapes_every_sink` |
| 2 | JS sinks: run data reaches the page only as JSON from the API (exports: as escaped script data), never as code; no `eval`, `Function`, `document.write` | `tests/test_security_checklist.py::Viewer::test_hostile_run_data_is_served_as_json_data`, `tests/test_security_checklist.py::Page::test_no_url_or_code_sink_takes_data`, `tests/test_observe_render.py::HostileBundleRendersInert::test_replay_embeds_hostile_strings_only_as_script_data` |
| 3 | URL sinks: no `href`, `src` or `action` takes data, so a `javascript:` value stays text | `tests/test_security_checklist.py::Page::test_no_url_or_code_sink_takes_data` |
| 4 | Unicode tricks: bidi controls and invisible format characters in tool names, args or tenant names are shown as `\uXXXX` | `tests/test_security_checklist.py::Page::test_esc_neutralises_markup_quotes_and_format_characters` |
| 5 | Strict CSP: `default-src 'none'`, `script-src` a fresh nonce per response, no `unsafe-inline` script, no inline handlers, `base-uri` and `form-action` `'none'` | `tests/test_observe_render.py::ObserverHttp::test_csp_uses_a_fresh_nonce_and_no_unsafe_inline_script`, `tests/test_security_checklist.py::Viewer::test_page_headers` |
| 6 | `frame-ancestors 'none'` | `tests/test_security_checklist.py::Viewer::test_page_headers` |
| 7 | `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff` on every browser-surface answer, errors included | `tests/test_security_checklist.py::Surfaces::test_refusals_carry_no_internals_or_credentials`, `tests/test_security_checklist.py::Viewer::test_page_headers` |
| 8 | Cookie auth: the session cookie is `HttpOnly; SameSite=Strict`, `Secure` over HTTPS, derived from the token (never the token) | `tests/test_observe_render.py::ObserverHttp::test_token_is_exchanged_for_a_cookie_and_leaves_the_url`, `tests/test_view.py::View::test_https_serves_with_a_secure_cookie` |
| 9 | API surfaces: bearer, mTLS or service-account credentials only, checked on every request; Slack callbacks: a v0 signature over the body, a timestamp within 5 minutes and a signature never seen before | `tests/test_slack_approvals.py::TestSignature::test_bad_signature_old_timestamp_and_replay_are_refused`, `tests/test_http_transport.py::TestLimits::test_bearer_token_and_keep_alive`, `tests/test_gateway.py::TestAuth::test_refusals_never_reach_the_upstream`, `tests/test_ingest.py::EndToEnd::test_http_level_rejections` |
| 10 | CSRF: no state-changing request is served to a cookie session (the viewer answers `GET` only); approvals are decided over the signer RPC by an authenticated identity, which a browser cannot attach cross-site | `tests/test_security_checklist.py::Viewer::test_no_state_changing_request_is_served_to_a_session` |
| 11 | Tenant scoping on every read: an identity of tenant B cannot read or act on tenant A's runs or approvals; a run token works only for its run, identity and tenant. The laptop viewer has one operator credential over one store (no per-tenant session) | `tests/test_http_transport.py::TestCrossTenant::test_matrix`, `tests/test_gateway.py::TestAuth::test_refusals_never_reach_the_upstream`, `tests/test_view.py::View::test_loopback_viewer_prints_a_token_url_and_needs_it` |
| 12 | No secret or token stays in a URL: the viewer's printed `?token=` is exchanged once for the cookie and answered with a redirect to a URL without it; only the page path exchanges it | `tests/test_observe_render.py::ObserverHttp::test_token_is_exchanged_for_a_cookie_and_leaves_the_url` |
| 13 | No secret or token in logs: handlers log no request line; refusals echo no credential | `tests/test_security_checklist.py::Surfaces::test_refusals_carry_no_internals_or_credentials`, `tests/test_remote_tokens.py::TestRemoteSigner::test_refusals_carry_no_log_state` |
| 14 | Request size limits: an oversized body is refused with 413 before it is read | `tests/test_security_checklist.py::Surfaces::test_refusals_carry_no_internals_or_credentials`, `tests/test_http_transport.py::TestLimits::test_oversize_body_is_refused`, `tests/test_gateway.py::TestExchange::test_bodies_are_capped` |
| 15 | Rate and connection limits: failed authentications limited per address and in total; per-client rate limit on ingest; slow clients cut off | `tests/test_remote_tokens.py::TestFailedAuth::test_limited_per_address_and_bounded`, `tests/test_ingest.py::EndToEnd::test_rate_limit`, `tests/test_http_transport.py::TestLimits::test_slow_client_is_cut_off` |
| 16 | Error bodies without internals: no traceback, source path or credential | `tests/test_security_checklist.py::Surfaces::test_refusals_carry_no_internals_or_credentials`, `tests/test_otlp.py::Wire::test_hostile_input_is_refused_cleanly` |
| 17 | HTTPS required off loopback: the viewer, the signer's `http` section, the issuer, ingest, the witness and the Slack bridge refuse plain HTTP beyond loopback (ingest and witness take `--insecure-http`, the Slack bridge `insecure_http: true`, for TLS terminated in front); the observer and the OTLP receiver serve loopback only; metrics need `allow_remote: true` and serve public data only | `tests/test_view.py::View::test_beyond_loopback_needs_https`, `tests/test_http_transport.py::TestConfig::test_tls_required_except_explicit_insecure_loopback`, `tests/test_security_checklist.py::PlainHttp::test_plain_http_beyond_loopback_is_refused`, `tests/test_signer_metrics.py::TestListen::test_non_loopback_needs_allow_remote`, `tests/test_slack_approvals.py::TestConfig::test_secrets_come_from_files_and_beyond_loopback_needs_tls` |
| 18 | Host check: the browser surface serves only the names it expects, other names only with the token (DNS rebinding) | `tests/test_observe_render.py::ObserverHttp::test_loopback_without_token_still_refuses_foreign_hosts`, `tests/test_observe_render.py::ObserverHttp::test_wildcard_bind_accepts_its_own_host_only_with_the_token` |
| 19 | Verdicts the server computes are labelled "operator-side view — re-verify with the signed release for evidence" | `tests/test_view.py::View::test_dev_run_is_listed_with_its_counts_and_verified_while_the_signer_holds_the_lock`, `tests/test_view.py::View::test_tampered_record_shows_only_the_failure` |
| 20 | The viewer refuses a run that fails verification: only the failure report is shown | `tests/test_view.py::View::test_tampered_record_shows_only_the_failure`, `tests/test_observe_render.py::ObserveBundle::test_tampered_bundle_is_refused` |
| 21 | Every HTTP handler is listed here and probed | `tests/test_security_checklist.py::Checklist::test_every_http_handler_is_listed`, `tests/test_security_checklist.py::Surfaces::test_every_surface_has_probes` |

## Adding a surface

Add the handler to `SURFACES` and `Surfaces.PROBES` in `tests/test_security_checklist.py` and to the Surfaces table
above, and make it pass every item that applies to its kind.
