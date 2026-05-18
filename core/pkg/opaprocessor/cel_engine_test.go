package opaprocessor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempVAP(t *testing.T, controlName, vapYAML string) string {
	t.Helper()
	tmpDir := t.TempDir()
	dir := filepath.Join(tmpDir, "cel-admission-library", "controls", controlName)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(vapYAML), 0644))
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })
	os.Chdir(tmpDir)
	return tmpDir
}

const privilegedVAP = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test-deny-privileged
spec:
  validations:
  - expression: "object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged == false)"
    message: "Privileged containers are not allowed"
`

func TestRunCELOnK8s_PrivilegedDenied(t *testing.T) {
	writeTempVAP(t, "test-deny-privileged", privilegedVAP)
	opap := &OPAProcessor{}
	rule := &reporthandling.PolicyRule{
		Name:         "test-deny-privileged",
		RuleLanguage: reporthandling.CELLanguage,
	}
	pod := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "bad-pod"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name": "c1",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}
	resp, err := opap.runCELOnK8s(context.Background(), rule, []map[string]interface{}{pod})
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "failed", resp[0].RuleStatus)
	assert.Contains(t, resp[0].AlertMessage, "bad-pod")
}

func TestRunCELOnK8s_AllowedPod(t *testing.T) {
	writeTempVAP(t, "test-deny-privileged", privilegedVAP)
	opap := &OPAProcessor{}
	rule := &reporthandling.PolicyRule{
		Name:         "test-deny-privileged",
		RuleLanguage: reporthandling.CELLanguage,
	}
	pod := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "good-pod"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":            "c1",
					"securityContext": map[string]interface{}{"privileged": false},
				},
			},
		},
	}
	resp, err := opap.runCELOnK8s(context.Background(), rule, []map[string]interface{}{pod})
	require.NoError(t, err)
	assert.Len(t, resp, 0)
}

func TestRunCELOnK8s_MissingVAP(t *testing.T) {
	tmpDir := t.TempDir()
	orig, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(orig) })
	os.Chdir(tmpDir)

	opap := &OPAProcessor{}
	rule := &reporthandling.PolicyRule{
		Name:         "nonexistent-control",
		RuleLanguage: reporthandling.CELLanguage,
	}
	_, err := opap.runCELOnK8s(context.Background(), rule, []map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CEL: failed to read VAP")
}
