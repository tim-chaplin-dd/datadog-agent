//go:build netbsd || openbsd || solaris || dragonfly || linux
// +build netbsd openbsd solaris dragonfly linux

package constants

const (
	//DefaultDogstatsDLogFile points to the dogstatsd stats log file that will be used if not configured
	DefaultDogstatsDLogFile = "/var/log/datadog/dogstatsd-stats.log"
)
