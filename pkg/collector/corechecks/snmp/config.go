package snmp

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"gopkg.in/yaml.v2"
	"path/filepath"
	"strings"
)

var defaultOidBatchSize = 60
var defaultPort = uint16(161)
var defaultRetries = 3
var defaultTimeout = 2

type snmpInitConfig struct {
	Profiles      profilesConfig  `yaml:"profiles"`
	GlobalMetrics []metricsConfig `yaml:"global_metrics"`
}

type snmpInstanceConfig struct {
	IPAddress       string `yaml:"ip_address"`
	Port            uint16 `yaml:"port"`
	CommunityString string `yaml:"community_string"`
	SnmpVersion     string `yaml:"snmp_version"`
	Timeout         int    `yaml:"timeout"`
	Retries         int    `yaml:"retries"`
	User            string `yaml:"user"`
	AuthProtocol    string `yaml:"authProtocol"`
	AuthKey         string `yaml:"authKey"`
	PrivProtocol    string `yaml:"privProtocol"`
	PrivKey         string `yaml:"privKey"`
	ContextName     string `yaml:"context_name"`

	// Related parse metric code: https://github.com/DataDog/integrations-core/blob/86e9dc09f5a1829a8e8bf1b404c4fb73a392e0e5/snmp/datadog_checks/snmp/parsing/metrics.py#L94-L150
	Metrics    []metricsConfig   `yaml:"metrics"`
	MetricTags []metricTagConfig `yaml:"metric_tags"`

	// Profile and Metrics configs
	Profile          string `yaml:"profile"`
	UseGlobalMetrics bool   `yaml:"use_global_metrics"`
}

type snmpConfig struct {
	ipAddress         string
	port              uint16
	communityString   string
	snmpVersion       string
	timeout           int
	retries           int
	user              string
	authProtocol      string
	authKey           string
	privProtocol      string
	privKey           string
	contextName       string
	oidConfig         oidConfig
	metrics           []metricsConfig
	metricTags        []metricTagConfig
	oidBatchSize      int
	profiles          profileDefinitionMap
	profileTags       []string
	uptimeMetricAdded bool
}

func (c *snmpConfig) refreshWithProfile(profile string) error {
	if _, ok := c.profiles[profile]; !ok {
		return fmt.Errorf("unknown profile '%s'", profile)
	}
	log.Debugf("Refreshing with profile `%s` with content: %#v", profile, c.profiles[profile])
	tags := []string{"snmp_profile:" + profile}
	definition := c.profiles[profile]

	// https://github.com/DataDog/integrations-core/blob/e64e2d18529c6c106f02435c5fdf2621667c16ad/snmp/datadog_checks/snmp/config.py#L181-L200
	c.metrics = append(c.metrics, definition.Metrics...)
	c.metricTags = append(c.metricTags, definition.MetricTags...)
	c.oidConfig.scalarOids = append(c.oidConfig.scalarOids, parseScalarOids(definition.Metrics, definition.MetricTags)...)
	c.oidConfig.columnOids = append(c.oidConfig.columnOids, parseColumnOids(definition.Metrics)...)

	if definition.Device.Vendor != "" {
		tags = append(tags, "device_vendor:"+definition.Device.Vendor)
	}
	c.profileTags = tags
	return nil
}

func (c *snmpConfig) addUptimeMetric() {
	if c.uptimeMetricAdded {
		return
	}
	metricConfig := getUptimeMetricConfig()
	c.metrics = append(c.metrics, metricConfig)
	c.oidConfig.scalarOids = append(c.oidConfig.scalarOids, metricConfig.Symbol.OID)
	c.uptimeMetricAdded = true
}

func (c *snmpConfig) getStaticTags() []string {
	tags := []string{"snmp_device:" + c.ipAddress}

	// TODO: Remove Telemetry
	tags = append(tags, "loader:core")
	return tags
}

func buildConfig(rawInstance integration.Data, rawInitConfig integration.Data) (snmpConfig, error) {
	instance := snmpInstanceConfig{}
	initConfig := snmpInitConfig{}

	// Set default before parsing
	instance.UseGlobalMetrics = true

	err := yaml.Unmarshal(rawInitConfig, &initConfig)
	if err != nil {
		return snmpConfig{}, err
	}

	err = yaml.Unmarshal(rawInstance, &instance)
	if err != nil {
		return snmpConfig{}, err
	}

	c := snmpConfig{}

	c.snmpVersion = instance.SnmpVersion

	// SNMP common connection configs
	c.ipAddress = instance.IPAddress
	c.port = instance.Port

	if instance.Port == 0 {
		c.port = defaultPort
	} else {
		c.port = instance.Port
	}

	if instance.Retries == 0 {
		c.retries = defaultRetries
	} else {
		c.retries = instance.Retries
	}

	if instance.Timeout == 0 {
		c.timeout = defaultTimeout
	} else {
		c.timeout = instance.Timeout
	}

	// SNMP connection configs
	c.communityString = instance.CommunityString
	c.user = instance.User
	c.authProtocol = instance.AuthProtocol
	c.authKey = instance.AuthKey
	c.privProtocol = instance.PrivProtocol
	c.privKey = instance.PrivKey
	c.contextName = instance.ContextName

	c.metrics = instance.Metrics

	c.oidBatchSize = defaultOidBatchSize

	// metrics Configs
	if instance.UseGlobalMetrics {
		c.metrics = append(c.metrics, initConfig.GlobalMetrics...)
	}
	// TODO: Validate c.metrics
	normalizeMetrics(c.metrics)

	c.metricTags = instance.MetricTags
	// TODO: Validate c.metricTags

	c.oidConfig.scalarOids = parseScalarOids(c.metrics, c.metricTags)
	c.oidConfig.columnOids = parseColumnOids(c.metrics)

	// Profile Configs
	var pConfig profilesConfig
	if len(initConfig.Profiles) > 0 {
		pConfig = initConfig.Profiles
	} else {
		pConfig = getDefaultProfilesDefinitionFiles()
	}
	profiles, err := loadProfiles(pConfig)
	if err != nil {
		return snmpConfig{}, fmt.Errorf("failed to load profiles: %s", err)
	}
	for _, profileDef := range profiles {
		normalizeMetrics(profileDef.Metrics)
	}

	c.profiles = profiles
	profile := instance.Profile

	if profile != "" {
		err = c.refreshWithProfile(profile)
		if err != nil {
			// TODO: test me
			return snmpConfig{}, fmt.Errorf("failed to refresh with profile: %s", err)
		}
	}

	// TODO: Add missing error handling by looking at
	//   https://github.com/DataDog/integrations-core/blob/e64e2d18529c6c106f02435c5fdf2621667c16ad/snmp/datadog_checks/snmp/config.py

	// TODO: Validate metrics
	//  - metrics
	//  - metricTags
	//  Cases:
	//   - index transform:
	//     https://github.com/DataDog/integrations-core/blob/d31d3532e16cf8418a8b112f47359f14be5ecae1/snmp/datadog_checks/snmp/parsing/metrics.py#L523-L537
	return c, err
}

func getUptimeMetricConfig() metricsConfig {
	// Reference sysUpTimeInstance directly, see http://oidref.com/1.3.6.1.2.1.1.3.0
	return metricsConfig{Symbol: symbolConfig{OID: "1.3.6.1.2.1.1.3.0", Name: "sysUpTimeInstance"}}
}

func parseScalarOids(metrics []metricsConfig, metricTags []metricTagConfig) []string {
	var oids []string
	for _, metric := range metrics {
		if metric.Symbol.OID != "" { // TODO: test me
			oids = append(oids, metric.Symbol.OID)
		}
	}
	for _, metricTag := range metricTags {
		if metricTag.OID != "" { // TODO: test me
			oids = append(oids, metricTag.OID)
		}
	}
	return oids
}

func parseColumnOids(metrics []metricsConfig) []string {
	var oids []string
	for _, metric := range metrics {
		if metric.Table.OID != "" { // TODO: test me
			for _, symbol := range metric.Symbols {
				oids = append(oids, symbol.OID)
			}
			for _, metricTag := range metric.MetricTags {
				if metricTag.Column.OID != "" {
					oids = append(oids, metricTag.Column.OID)
				}
			}
		}
	}
	return oids
}

func getProfileForSysObjectID(profiles profileDefinitionMap, sysObjectID string) (string, error) {
	sysOidToProfile := map[string]string{}
	var matchedOids []string

	// TODO: Test me
	sysObjectID = strings.TrimLeft(sysObjectID, ".")

	// TODO: Test me
	for profile, definition := range profiles {
		// TODO: Check for duplicate profile sysobjectid
		//   https://github.com/DataDog/integrations-core/blob/df2bc0d17af490491651d7578e67d9928941df62/snmp/datadog_checks/snmp/snmp.py#L142-L144
		for _, oidPattern := range definition.SysObjectIds {

			found, err := filepath.Match(oidPattern, sysObjectID)
			if err != nil {
				log.Debugf("pattern error: %s", err)
				continue
			}
			if found {
				sysOidToProfile[oidPattern] = profile
				matchedOids = append(matchedOids, oidPattern)
			}
		}
	}
	oid, err := getMostSpecificOid(matchedOids)
	if err != nil {
		return "", fmt.Errorf("failed to get most specific profile for sysObjectID `%s`, for matched oids %v: %s", sysObjectID, matchedOids, err)
	}
	return sysOidToProfile[oid], nil
}
