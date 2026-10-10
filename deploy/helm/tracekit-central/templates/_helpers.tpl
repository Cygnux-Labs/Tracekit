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
