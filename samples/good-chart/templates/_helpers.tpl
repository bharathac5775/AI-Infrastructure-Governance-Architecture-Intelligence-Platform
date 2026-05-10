{{- define "good-chart.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "good-chart.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "good-chart.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "good-chart.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "good-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "good-chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "good-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
