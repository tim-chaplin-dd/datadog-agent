// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/java"
	nettelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
)

const (
	AgentUSMJar = "agent-usm.jar"
)

var (
	// path to our java USM agent TLS tracer
	javaUSMAgentJarPath = ""

	// default arguments passed to the injected agent-usm.jar
	javaUSMAgentArgs = ""
	// authID is used here as an identifier, simple proof of authenticity
	// between the injected java process and the ebpf ioctl that receive the payload
	authID = int64(0)

	// The regex is matching against /proc/pid/cmdline
	// if matching the agent-usm.jar would or not injected
	javaAgentAllowListRegex *regexp.Regexp
	javaAgentBlockListRegex *regexp.Regexp
)

type JavaTLSProgram struct {
	processMonitor *monitor.ProcessMonitor
	cleanupExec    func()
}

// Static evaluation to make sure we are not breaking the interface.
var _ subprogram = &JavaTLSProgram{}

func newJavaTLSProgram(c *config.Config) *JavaTLSProgram {
	var err error

	if !c.EnableHTTPSMonitoring || !c.EnableJavaTLSSupport {
		return nil
	}

	javaUSMAgentArgs = c.JavaAgentArgs
	if c.JavaAgentAllowList != "" {
		javaAgentAllowListRegex, err = regexp.Compile(c.JavaAgentAllowList)
		if err != nil {
			javaAgentAllowListRegex = nil
			log.Errorf("JavaAgentAllowList regex can't be compiled %s", err)
		}
	}
	if c.JavaAgentBlockList != "" {
		javaAgentBlockListRegex, err = regexp.Compile(c.JavaAgentBlockList)
		if err != nil {
			javaAgentBlockListRegex = nil
			log.Errorf("JavaAgentBlockList regex can't be compiled %s", err)
		}
	}

	javaUSMAgentJarPath = filepath.Join(c.JavaDir, AgentUSMJar)
	jar, err := os.Open(javaUSMAgentJarPath)
	if err != nil {
		log.Errorf("java TLS can't access to agent-usm.jar file %s : %s", javaUSMAgentJarPath, err)
		return nil
	}
	jar.Close()

	mon := monitor.GetProcessMonitor()
	return &JavaTLSProgram{
		processMonitor: mon,
	}
}

func (p *JavaTLSProgram) ConfigureManager(m *nettelemetry.Manager) {
	rand.Seed(int64(os.Getpid()) + time.Now().UnixMicro())
	authID = rand.Int63()
}

func (p *JavaTLSProgram) ConfigureOptions(options *manager.Options) {}

func (p *JavaTLSProgram) GetAllUndefinedProbes() (probeList []manager.ProbeIdentificationPair) {
	return
}

func allowBlockAttachment(pid uint32) (reject bool) {
	// filter is disabled (default configuration)
	if javaAgentAllowListRegex == nil && javaAgentBlockListRegex == nil {
		return false
	}

	procCmdline := fmt.Sprintf("%s/%d/cmdline", util.HostProc(), pid)
	cmd, err := os.ReadFile(procCmdline)
	if err != nil {
		log.Debugf("can't open %s : %s", procCmdline, err)
		return true
	}
	fullCmdline := strings.ReplaceAll(string(cmd), "\000", " ")

	// Allow have an higher priority
	if javaAgentAllowListRegex != nil && javaAgentAllowListRegex.MatchString(fullCmdline) {
		return false
	}
	if javaAgentBlockListRegex != nil && javaAgentBlockListRegex.MatchString(fullCmdline) {
		return true
	}
	// by default we attach the java process
	return false
}

func newJavaProcess(pid uint32) {
	if allowBlockAttachment(pid) {
		log.Debugf("java pid %d attachment rejected by blocklist")
		return
	}

	args := javaUSMAgentArgs
	if len(args) > 0 {
		args += " "
	}
	args += "dd.usm.authID=" + strconv.FormatInt(authID, 10)
	if err := java.InjectAgent(int(pid), javaUSMAgentJarPath, args); err != nil {
		log.Error(err)
	}
}

func (p *JavaTLSProgram) Start() {
	var err error
	p.cleanupExec, err = p.processMonitor.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXEC,
		Metadata: monitor.NAME,
		Regex:    regexp.MustCompile("^java$"),
		Callback: newJavaProcess,
	})
	if err != nil {
		log.Errorf("process monitor Subscribe() error: %s", err)
		return
	}
}

func (p *JavaTLSProgram) Stop() {
	if p.cleanupExec != nil {
		p.cleanupExec()
	}
}
