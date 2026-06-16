{{- define "presidio-scout.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "presidio-scout.labels" -}}
app.kubernetes.io/name: presidio-scout
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* The shared, hardened pod template used by both the Job and the CronJob. */}}
{{- define "presidio-scout.podTemplate" -}}
metadata:
  labels:
    app.kubernetes.io/name: presidio-scout
    {{- if .Values.azureWorkloadIdentity }}
    azure.workload.identity/use: "true"
    {{- end }}
spec:
  serviceAccountName: {{ .Values.serviceAccount.name }}
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    {{- toYaml .Values.podSecurityContext | nindent 4 }}
  containers:
    - name: scout
      image: {{ include "presidio-scout.image" . | quote }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      args:
        - {{ .Values.provider | quote }}
        - --report-dir
        - {{ .Values.reportDir | quote }}
        {{- if .Values.requireShortLivedCreds }}
        - --require-short-lived-creds
        {{- end }}
        {{- if .Values.failOnFinding }}
        - --fail-on-finding
        - {{ .Values.failOnFinding | quote }}
        {{- end }}
        {{- range .Values.extraArgs }}
        - {{ . | quote }}
        {{- end }}
      securityContext:
        {{- toYaml .Values.containerSecurityContext | nindent 8 }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: report
          mountPath: {{ .Values.reportDir | quote }}
  volumes:
    - name: tmp
      emptyDir: {}
    - name: report
      emptyDir: {}
{{- end -}}
