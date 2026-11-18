{{- /* The number of logs: one per replica the StatefulSet can reach. */ -}}
{{- define "tc.logs" -}}
{{- ternary .Values.autoscaling.maxReplicas .Values.replicas .Values.autoscaling.enabled | int -}}
{{- end -}}

{{- define "tc.labels" -}}
app.kubernetes.io/name: tracekit-central
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "tc.hardened" -}}
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities: {drop: [ALL]}
seccompProfile: {type: RuntimeDefault}
{{- end -}}

{{- /* "4" or "6" for an IPv4 or IPv6 address (no prefix length), "" for anything else. */ -}}
{{- define "tc.ipFamily" -}}
{{- $octet := `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])` -}}
{{- if regexMatch (printf `^%s(\.%s){3}$` $octet $octet) . -}}4
{{- else if regexMatch `^[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}$` . -}}6
{{- end -}}
{{- end -}}
