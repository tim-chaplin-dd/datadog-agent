// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package status

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"text/template"

	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/otlp"
	"github.com/DataDog/datadog-agent/pkg/snmp/traps"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var fmap = Textfmap()

// FormatStatus takes a json bytestring and prints out the formatted statuspage
func FormatStatus(data []byte) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	forwarderStats := stats["forwarderStats"]
	if forwarderStatsMap, ok := forwarderStats.(map[string]interface{}); ok {
		forwarderStatsMap["config"] = stats["config"]
	} else {
		log.Warn("The Forwarder status format is invalid. Some parts of the `Forwarder` section may be missing.")
	}
	runnerStats := stats["runnerStats"]
	pyLoaderStats := stats["pyLoaderStats"]
	pythonInit := stats["pythonInit"]
	autoConfigStats := stats["autoConfigStats"]
	checkSchedulerStats := stats["checkSchedulerStats"]
	aggregatorStats := stats["aggregatorStats"]
	s, err := check.TranslateEventPlatformEventTypes(aggregatorStats)
	if err != nil {
		log.Debugf("failed to translate event platform event types in aggregatorStats: %s", err.Error())
	} else {
		aggregatorStats = s
	}
	dogstatsdStats := stats["dogstatsdStats"]
	logsStats := stats["logsStats"]
	dcaStats := stats["clusterAgentStatus"]
	endpointsInfos := stats["endpointsInfos"]
	inventoriesStats := stats["inventories"]
	systemProbeStats := stats["systemProbeStats"]
	processAgentStatus := stats["processAgentStatus"]
	snmpTrapsStats := stats["snmpTrapsStats"]
	title := fmt.Sprintf("Agent (v%s)", stats["version"])
	stats["title"] = title

	headerFunc := func() { RenderStatusTemplate(b, "/header.tmpl", stats) }
	checkStatsFunc := func() {
		renderChecksStats(b, runnerStats, pyLoaderStats, pythonInit, autoConfigStats, checkSchedulerStats,
			inventoriesStats, "")
	}
	jmxFetchFunc := func() { RenderStatusTemplate(b, "/jmxfetch.tmpl", stats) }
	forwarderFunc := func() { RenderStatusTemplate(b, "/forwarder.tmpl", forwarderStats) }
	endpointsFunc := func() { RenderStatusTemplate(b, "/endpoints.tmpl", endpointsInfos) }
	logsAgentFunc := func() { RenderStatusTemplate(b, "/logsagent.tmpl", logsStats) }
	systemProbeFunc := func() {
		if config.Datadog.GetBool("system_probe_config.enabled") {
			RenderStatusTemplate(b, "/systemprobe.tmpl", systemProbeStats)
		}
	}
	processAgentFunc := func() { RenderStatusTemplate(b, "/process-agent.tmpl", processAgentStatus) }
	traceAgentFunc := func() { RenderStatusTemplate(b, "/trace-agent.tmpl", stats["apmStats"]) }
	aggregatorFunc := func() { RenderStatusTemplate(b, "/aggregator.tmpl", aggregatorStats) }
	dogstatsdFunc := func() { RenderStatusTemplate(b, "/dogstatsd.tmpl", dogstatsdStats) }
	clusterAgentFunc := func() {
		if config.Datadog.GetBool("cluster_agent.enabled") || config.Datadog.GetBool("cluster_checks.enabled") {
			RenderStatusTemplate(b, "/clusteragent.tmpl", dcaStats)
		}
	}
	snmpTrapFunc := func() {
		if traps.IsEnabled() {
			RenderStatusTemplate(b, "/snmp-traps.tmpl", snmpTrapsStats)
		}
	}
	autodiscoveryFunc := func() {
		if config.IsContainerized() {
			renderAutodiscoveryStats(b, stats["adEnabledFeatures"], stats["adConfigErrors"],
				stats["filterErrors"])
		}
	}

	otlpFunc := func() {
		if otlp.IsDisplayed() {
			RenderStatusTemplate(b, "/otlp.tmpl", stats)
		}
	}

	var renderFuncs []func()

	if config.IsCLCRunner() {
		renderFuncs = []func(){headerFunc, checkStatsFunc, aggregatorFunc, endpointsFunc, clusterAgentFunc,
			autodiscoveryFunc}
	} else {
		renderFuncs = []func(){headerFunc, checkStatsFunc, jmxFetchFunc, forwarderFunc, endpointsFunc,
			logsAgentFunc, systemProbeFunc, processAgentFunc, traceAgentFunc, aggregatorFunc, dogstatsdFunc,
			clusterAgentFunc, snmpTrapFunc, autodiscoveryFunc, otlpFunc}
	}

	renderAgentSections(renderFuncs)

	return b.String(), nil
}

// FormatDCAStatus takes a json bytestring and prints out the formatted statuspage
func FormatDCAStatus(data []byte) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	forwarderStats := stats["forwarderStats"]
	runnerStats := stats["runnerStats"]
	autoConfigStats := stats["autoConfigStats"]
	checkSchedulerStats := stats["checkSchedulerStats"]
	endpointsInfos := stats["endpointsInfos"]
	logsStats := stats["logsStats"]
	orchestratorStats := stats["orchestrator"]
	title := fmt.Sprintf("Datadog Cluster Agent (v%s)", stats["version"])
	stats["title"] = title
	RenderStatusTemplate(b, "/header.tmpl", stats)
	renderChecksStats(b, runnerStats, nil, nil, autoConfigStats, checkSchedulerStats, nil, "")
	RenderStatusTemplate(b, "/forwarder.tmpl", forwarderStats)
	RenderStatusTemplate(b, "/endpoints.tmpl", endpointsInfos)
	if config.Datadog.GetBool("compliance_config.enabled") {
		RenderStatusTemplate(b, "/logsagent.tmpl", logsStats)
	}
	if config.Datadog.GetBool("orchestrator_explorer.enabled") {
		RenderStatusTemplate(b, "/orchestrator.tmpl", orchestratorStats)
	}

	return b.String(), nil
}

// FormatHPAStatus takes a json bytestring and prints out the formatted statuspage
func FormatHPAStatus(data []byte) (string, error) {
	var b = new(bytes.Buffer)
	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	RenderStatusTemplate(b, "/custommetricsprovider.tmpl", stats)
	return b.String(), nil
}

// FormatSecurityAgentStatus takes a json bytestring and prints out the formatted status for security agent
func FormatSecurityAgentStatus(data []byte) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	runnerStats := stats["runnerStats"]
	complianceChecks := stats["complianceChecks"]
	complianceStatus := stats["complianceStatus"]
	title := fmt.Sprintf("Datadog Security Agent (v%s)", stats["version"])
	stats["title"] = title
	RenderStatusTemplate(b, "/header.tmpl", stats)

	renderRuntimeSecurityStats(b, stats["runtimeSecurityStatus"])
	renderComplianceChecksStats(b, runnerStats, complianceChecks, complianceStatus)

	return b.String(), nil
}

// FormatProcessAgentStatus takes a json bytestring and prints out the formatted status for process-agent
func FormatProcessAgentStatus(data []byte) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	RenderStatusTemplate(b, "/process-agent.tmpl", stats)

	return b.String(), nil
}

// FormatMetadataMapCLI builds the rendering in the metadataMapper template.
func FormatMetadataMapCLI(data []byte) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	err := json.Unmarshal(data, &stats)
	if err != nil {
		return b.String(), err
	}
	RenderStatusTemplate(b, "/metadatamapper.tmpl", stats)
	return b.String(), nil
}

func renderChecksStats(w io.Writer, runnerStats, pyLoaderStats, pythonInit, autoConfigStats, checkSchedulerStats, inventoriesStats interface{}, onlyCheck string) {
	checkStats := make(map[string]interface{})
	checkStats["RunnerStats"] = runnerStats
	checkStats["pyLoaderStats"] = pyLoaderStats
	checkStats["pythonInit"] = pythonInit
	checkStats["AutoConfigStats"] = autoConfigStats
	checkStats["CheckSchedulerStats"] = checkSchedulerStats
	checkStats["OnlyCheck"] = onlyCheck
	checkStats["CheckMetadata"] = inventoriesStats
	RenderStatusTemplate(w, "/collector.tmpl", checkStats)
}

func renderCheckStats(data []byte, checkName string) (string, error) {
	var b = new(bytes.Buffer)

	stats := make(map[string]interface{})
	json.Unmarshal(data, &stats) //nolint:errcheck
	runnerStats := stats["runnerStats"]
	pyLoaderStats := stats["pyLoaderStats"]
	pythonInit := stats["pythonInit"]
	autoConfigStats := stats["autoConfigStats"]
	checkSchedulerStats := stats["checkSchedulerStats"]
	inventoriesStats := stats["inventories"]
	renderChecksStats(b, runnerStats, pyLoaderStats, pythonInit, autoConfigStats, checkSchedulerStats, inventoriesStats, checkName)

	return b.String(), nil
}

func renderComplianceChecksStats(w io.Writer, runnerStats interface{}, complianceChecks, complianceStatus interface{}) {
	checkStats := make(map[string]interface{})
	checkStats["RunnerStats"] = runnerStats
	checkStats["ComplianceStatus"] = complianceStatus
	checkStats["ComplianceChecks"] = complianceChecks
	RenderStatusTemplate(w, "/compliance.tmpl", checkStats)
}

func renderRuntimeSecurityStats(w io.Writer, runtimeSecurityStatus interface{}) {
	status := make(map[string]interface{})
	status["RuntimeSecurityStatus"] = runtimeSecurityStatus
	RenderStatusTemplate(w, "/runtimesecurity.tmpl", status)
}

func renderAutodiscoveryStats(w io.Writer, adEnabledFeatures interface{}, adConfigErrors interface{}, filterErrors interface{}) {
	autodiscoveryStats := make(map[string]interface{})
	autodiscoveryStats["adEnabledFeatures"] = adEnabledFeatures
	autodiscoveryStats["adConfigErrors"] = adConfigErrors
	autodiscoveryStats["filterErrors"] = filterErrors
	RenderStatusTemplate(w, "/autodiscovery.tmpl", autodiscoveryStats)
}

//go:embed templates
var templatesFS embed.FS

// RenderStatusTemplate takes a templateName, finds the corresponding template file, and renders it into the provided io.Writer
func RenderStatusTemplate(w io.Writer, templateName string, stats interface{}) {
	tmpl, tmplErr := templatesFS.ReadFile(path.Join("templates", templateName))
	if tmplErr != nil {
		fmt.Println(tmplErr)
		return
	}
	t := template.Must(template.New(templateName).Funcs(fmap).Parse(string(tmpl)))
	err := t.Execute(w, stats)
	if err != nil {
		fmt.Println(err)
	}
}

func renderAgentSections(renderFuncs []func()) {
	for _, f := range renderFuncs {
		f()
	}
}
