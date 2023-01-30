package constants

const (
	// DefaultConfPath points to the folder containing datadog.yaml
	DefaultConfPath = "/opt/datadog-agent/etc"
	// DefaultLogFile points to the log file that will be used if not configured
	DefaultLogFile = "/opt/datadog-agent/logs/agent.log"
	// DefaultDCALogFile points to the log file that will be used if not configured
	DefaultDCALogFile = "/opt/datadog-agent/logs/cluster-agent.log"
	//DefaultJmxLogFile points to the jmx fetch log file that will be used if not configured
	DefaultJmxLogFile = "/opt/datadog-agent/logs/jmxfetch.log"
	// DefaultCheckFlareDirectory a flare friendly location for checks to be written
	DefaultCheckFlareDirectory = "/opt/datadog-agent/logs/checks/"
	// DefaultJMXFlareDirectory a flare friendly location for jmx command logs to be written
	DefaultJMXFlareDirectory = "/opt/datadog-agent/logs/jmxinfo/"
	//DefaultDogstatsDLogFile points to the dogstatsd stats log file that will be used if not configured
	DefaultDogstatsDLogFile = "/opt/datadog-agent/logs/dogstatsd_info/dogstatsd-stats.log"
)
