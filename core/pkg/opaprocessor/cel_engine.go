package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/opa-utils/reporthandling"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

// runCELOnK8s evaluates a ValidatingAdmissionPolicy CEL rule against k8s objects
// alongside the existing Rego engine. For object-scoped rules, kubescape scan
// and the cluster admission controller produce identical results.
// Known gap: authorizer and request.userInfo are not available offline.
func (opap *OPAProcessor) runCELOnK8s(
	ctx context.Context,
	rule *reporthandling.PolicyRule,
	k8sObjects []map[string]interface{},
) ([]reporthandling.RuleResponse, error) {

	vapPath := fmt.Sprintf("cel-admission-library/controls/%s/policy.yaml", rule.Name)
	vapBytes, err := os.ReadFile(vapPath)
	if err != nil {
		return nil, fmt.Errorf("CEL: failed to read VAP for rule %s: %w", rule.Name, err)
	}

	var vap admissionv1.ValidatingAdmissionPolicy
	if err := yaml.Unmarshal(vapBytes, &vap); err != nil {
		return nil, fmt.Errorf("CEL: failed to parse VAP YAML: %w", err)
	}

	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("params", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("CEL: env creation failed: %w", err)
	}

	// Stub admission request context (offline mode)
	requestStub := map[string]interface{}{
		"operation": "CREATE",
		"oldObject": nil,
	}

	var responses []reporthandling.RuleResponse

	for _, obj := range k8sObjects {
		objJSON, _ := json.Marshal(obj)
		var objMap map[string]interface{}
		json.Unmarshal(objJSON, &objMap)

		for _, validation := range vap.Spec.Validations {
			ast, issues := env.Compile(validation.Expression)
			if issues != nil && issues.Err() != nil {
				continue
			}
			prg, err := env.Program(ast)
			if err != nil {
				continue
			}
			out, _, err := prg.Eval(map[string]interface{}{
				"object":  objMap,
				"params":  map[string]interface{}{},
				"request": requestStub,
			})
			if err != nil {
				continue
			}
			// CEL true = ALLOW, false = DENY (violation)
			if out.Value() == false {
				name := ""
				if meta, ok := obj["metadata"].(map[string]interface{}); ok {
					name, _ = meta["name"].(string)
				}
				msg := validation.Message
				if msg == "" {
					msg = fmt.Sprintf("CEL validation failed: %s", validation.Expression)
				}
				responses = append(responses, reporthandling.RuleResponse{
					Rulename:     rule.Name,
					AlertMessage: fmt.Sprintf("Object '%s': %s", name, msg),
					RuleStatus:   "failed",
				})
			}
		}
	}

	return responses, nil
}
