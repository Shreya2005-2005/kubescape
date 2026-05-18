# CEL Rule Engine for Kubescape

## Motivation
Kubescape evaluates controls using OPA/Rego. Kubernetes ships native
`ValidatingAdmissionPolicy` (VAP) resources using CEL. The
`kubescape/cel-admission-library` already ships Kubescape controls as VAP
YAML — but Kubescape cannot evaluate them locally, so a resource passing
`kubescape scan` may still fail cluster admission.

This proposal adds a native CEL engine running **alongside** Rego, using the
same `google/cel-go` library Kubernetes uses internally.

## Design

### Extension point
`core/pkg/opaprocessor/processorhandler.go` dispatches on `rule.RuleLanguage`:

```go
case reporthandling.CELLanguage:
    return opap.runCELOnK8s(ctx, rule, k8sObjects)
```

### New constant
`opa-utils/reporthandling/datastructures.go`:
```go
CELLanguage RuleLanguages = "cel"
```

### Evaluation environment
| Variable | Offline (Kubescape) | Live admission |
|---|---|---|
| `object` | ✅ Full resource | ✅ Resource being admitted |
| `params` | ✅ From VAP bundle | ✅ From binding ParamRef |
| `request` | ⚠️ Stubbed: `operation=CREATE` | ✅ Full admission request |
| `oldObject` | ⚠️ null | ✅ Previous state |
| `authorizer` | ❌ Not available offline (documented gap) | ✅ Full RBAC |

### Rule loading
CEL rules load from `ValidatingAdmissionPolicy` YAML in `cel-admission-library`
— same files the library releases. Result violations map to
`reporthandling.RuleResponse` — identical shape to Rego results, no downstream
changes needed.

## Scope
- `CELLanguage` constant in `opa-utils`
- `runCELOnK8s()` in `kubescape/core/pkg/opaprocessor/cel_engine.go`
- VAP YAML loading + CEL env setup with `google/cel-go`
- Admission request context stub (`request.operation=CREATE`, `oldObject=null`)
- Result mapping to `reporthandling.RuleResponse`
- Unit tests (3 passing)
- 6+ Rego controls converted to CEL in `cel-admission-library`
- Rego-to-CEL conversion guide in `regolibrary`

## Out of scope
- Deprecation of Rego engine
- MutatingAdmissionPolicy support
- Rules using `authorizer` or `request.userInfo`
- Reading deployed VAPs from a live cluster
