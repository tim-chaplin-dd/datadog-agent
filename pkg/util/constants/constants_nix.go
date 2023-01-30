//go:build netbsd || openbsd || solaris || dragonfly || linux
// +build netbsd openbsd solaris dragonfly linux

package constants

const (
	// DefaultConfPath points to the folder containing datadog.yaml
	DefaultConfPath = "/etc/datadog-agent"
	// DefaultLogFile points to the log file that will be used if not configured
	DefaultLogFile = "/var/log/datadog/agent.log"
	// DefaultDCALogFile points to the log file that will be used if not configured
	DefaultDCALogFile = "/var/log/datadog/cluster-agent.log"
	// DefaultJmxLogFile points to the jmx fetch log file that will be used if not configured
	DefaultJmxLogFile = "/var/log/datadog/jmxfetch.log"
	// DefaultCheckFlareDirectory a flare friendly location for checks to be written
	DefaultCheckFlareDirectory = "/var/log/datadog/checks/"
	// DefaultJMXFlareDirectory a flare friendly location for jmx command logs to be written
	DefaultJMXFlareDirectory = "/var/log/datadog/jmxinfo/"
	//DefaultDogstatsDLogFile points to the dogstatsd stats log file that will be used if not configured
	DefaultDogstatsDLogFile = "/var/log/datadog/dogstatsd_info/dogstatsd-stats.log"
)
