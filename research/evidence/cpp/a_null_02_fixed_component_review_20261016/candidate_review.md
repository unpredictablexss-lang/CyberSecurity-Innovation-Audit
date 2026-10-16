# A-NULL-02 fixed-component candidate review

This is a bounded source-bound review, not a vulnerability report.

## Root-cause aggregation

| root cause group | independent root causes | candidate sites | fixed sites | validated vulnerabilities |
|---|---:|---:|---:|---:|
| `A-NULL-02-RC-NOTHROW-CLIENTPROXY-ALLOC` | 1 | 5 | 5 | 0 |

## Candidate review table

| row | function | source relation | pointer sink | alias / rebind | guard/error path | classification |
|---|---|---|---|---|---|---|
| `A-NULL-02-ROW-01` | `ClinetOnNodeOnlineStateChanged` | L70: `clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);` | L71: `clientProxy->` | direct_binding_no_bounded_alias / rebind=false | none_before_sink | `plausible_unproven` |
| `A-NULL-02-ROW-02` | `ClinetOnNodeBasicInfoChanged` | L81: `clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);` | L82: `clientProxy->` | direct_binding_no_bounded_alias / rebind=false | none_before_sink | `plausible_unproven` |
| `A-NULL-02-ROW-03` | `ClientOnNodeStatusChanged` | L96: `clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);` | L97: `clientProxy->` | direct_binding_no_bounded_alias / rebind=false | none_before_sink | `plausible_unproven` |
| `A-NULL-02-ROW-04` | `ClinetOnLocalNetworkIdChanged` | L107: `clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);` | L108: `clientProxy->` | direct_binding_no_bounded_alias / rebind=false | none_before_sink | `plausible_unproven` |
| `A-NULL-02-ROW-05` | `ClinetNotifyDeviceNotTrusted` | L122: `clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);` | L123: `clientProxy->` | direct_binding_no_bounded_alias / rebind=false | none_before_sink | `plausible_unproven` |

The five rows are one independent root-cause group for counting; they are not five confirmed vulnerabilities.

## Fixed comparison

| row | function | allocation line | guard line | sink line | error path | classification |
|---|---|---:|---:|---:|---|---|
| `A-NULL-02-FIXED-01` | `ClinetOnNodeOnlineStateChanged` | 70 | 71 | 75 | local_early_return_shape | `refuted` |
| `A-NULL-02-FIXED-02` | `ClinetOnNodeBasicInfoChanged` | 85 | 86 | 90 | local_early_return_shape | `refuted` |
| `A-NULL-02-FIXED-03` | `ClientOnNodeStatusChanged` | 104 | 105 | 109 | local_early_return_shape | `refuted` |
| `A-NULL-02-FIXED-04` | `ClinetOnLocalNetworkIdChanged` | 119 | 120 | 124 | local_early_return_shape | `refuted` |
| `A-NULL-02-FIXED-05` | `ClinetNotifyDeviceNotTrusted` | 138 | 139 | 143 | local_early_return_shape | `refuted` |

`refuted` applies only to the local missing-guard relation; it is not a product safety verdict.

## Label policy

- `likely_false_positive`: A detector output contradicted by a fixed, safe, unrelated or non-pointer control.
- `plausible_unproven`: Exact bounded source/sink relation is present, but product trigger, attacker control, reachability or CIA impact is unproven.
- `refuted`: The candidate relation is absent or a local repair guard is present in the pinned comparison source; this is not a product safety proof.
- `insufficient_evidence`: Coverage, parse, macro/template, cross-function alias, build context or evidence obligations prevent a stronger classification.

## False-positive and noise analysis

| category | controls | expected findings | observed findings | classification |
|---|---:|---:|---:|---|
| fixed | 5 | 0 | 0 | `refuted` |
| positive | 6 | 6 | 6 | `plausible_unproven` |
| safe | 4 | 0 | 0 | `refuted` |
| unrelated | 4 | 0 | 0 | `refuted` |

All six positive controls retained one candidate each; no fixed, safe or unrelated control produced an unexpected finding. This is control evidence, not a precision/recall estimate.

## Unknown and non-upgrade reasons

- No real product entry or privilege boundary was established.
- No attacker-controlled allocation-failure trigger was demonstrated.
- No product build, macro/template instantiation or complete alias/CFG context was bound.
- No concrete confidentiality, integrity or availability impact was demonstrated.
- A historical advisory/CVE and fixed commit are context only and cannot upgrade a candidate.

Final state: `candidate/unassessed only; validated_vulnerability=0; no confirmed/reportable, CVE or product-safety claim`
