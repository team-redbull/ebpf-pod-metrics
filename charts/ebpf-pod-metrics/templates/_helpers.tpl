{{/* vim: set filetype=mustache: */}}

{{- define "ebpf-pod-metrics.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ebpf-pod-metrics.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ebpf-pod-metrics.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-pod-metrics.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ebpf-pod-metrics.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ebpf-pod-metrics.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Enabled programs, comma-separated and sorted. Fails on unknown names (no object in the chart)
and on an empty selection.
*/}}
{{- define "ebpf-pod-metrics.programs" -}}
{{- $out := list }}
{{- range $name, $p := .Values.programs }}
{{- if $p.enabled }}
{{- if not ($.Files.Get (printf "files/programs/%s.bpf.o" $name)) }}
{{- fail (printf "programs.%s: the chart has no files/programs/%s.bpf.o" $name $name) }}
{{- end }}
{{- $out = append $out $name }}
{{- end }}
{{- end }}
{{- if not $out }}
{{- fail "programs: enable at least one program" }}
{{- end }}
{{- join "," $out }}
{{- end }}

{{- define "ebpf-pod-metrics.hasProfile" -}}
{{- if has "node-cpu-profile" (splitList "," (include "ebpf-pod-metrics.programs" .)) }}true{{ end }}
{{- end }}

{{/*
Programs ConfigMap name: content-addressed, like kustomize's configMapGenerator. Any change to an
enabled object or config gives a new name, which rolls the DaemonSet; the ConfigMap can be immutable.
*/}}
{{- define "ebpf-pod-metrics.programsConfigMap" -}}
{{- $data := "" }}
{{- range $name := splitList "," (include "ebpf-pod-metrics.programs" .) }}
{{- $data = print $data $name ($.Files.Get (printf "files/programs/%s.yaml" $name)) ($.Files.Get (printf "files/programs/%s.bpf.o" $name)) }}
{{- end }}
{{- printf "%s-programs-%s" (include "ebpf-pod-metrics.fullname" .) (sha256sum $data | trunc 10) }}
{{- end }}

{{/* Linux capabilities: SYSLOG only when the kernel-function profiler needs /proc/kallsyms. */}}
{{- define "ebpf-pod-metrics.capabilities" -}}
{{- $caps := list "BPF" "PERFMON" "SYS_RESOURCE" }}
{{- if include "ebpf-pod-metrics.hasProfile" . }}
{{- $caps = append $caps "SYSLOG" }}
{{- end }}
{{- toJson $caps }}
{{- end }}

{{- define "ebpf-pod-metrics.sccName" -}}
{{- if .Values.scc.create }}
{{- include "ebpf-pod-metrics.fullname" . }}
{{- else }}
{{- required "scc.name is required when scc.create=false" .Values.scc.name }}
{{- end }}
{{- end }}

{{- define "ebpf-pod-metrics.image" -}}
{{- $repo := .Values.image.repository }}
{{- if .Values.image.registry }}
{{- $repo = printf "%s/%s" .Values.image.registry .Values.image.repository }}
{{- end }}
{{- if .Values.image.digest }}
{{- printf "%s@%s" $repo .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" $repo (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/* Fixed job label value, so dashboards and alerts don't depend on the release name. */}}
{{- define "ebpf-pod-metrics.jobLabel" -}}ebpf-pod-metrics.io/job{{- end }}
