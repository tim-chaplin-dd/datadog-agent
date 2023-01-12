// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/version"
)

const (
	expectedInfo = `=========================================
Processes and Containers Agent (v 0.99.0)
=========================================

  Pid: 485
  Hostname: ubuntu-1404.vagrantup.com
  Uptime: 3464 seconds
  Mem alloc: 2096792 bytes
  System Probe Process Module Status: Not running

  Last collection time: 2017-09-28 07:10:16
  Docker socket: /var/run/docker.sock
  Number of processes: 84
  Number of containers: 0
  Process Queue length: 0
  RTProcess Queue length: 0
  Connections Queue length: 0
  Event Queue length: 0
  Pod Queue length: 0
  Process Bytes enqueued: 0
  RTProcess Bytes enqueued: 0
  Connections Bytes enqueued: 0
  Event Bytes enqueued: 0
  Pod Bytes enqueued: 0
  Drop Check Payloads: []

  Logs: /var/log/datadog/process-agent.log

`
	notRunningInfo = `=========================================
Processes and Containers Agent (v 0.99.0)
=========================================

  Not running

`
	errInfo = `=========================================
Processes and Containers Agent (v 0.99.0)
=========================================

  Error: EOF

`
	expVarPath                             = "/debug/vars"
	sysProbeProcessModuleEnabledExpVarPath = "/debug/vars/sysprobeprocessmoduleon"
	expVarResponse                         = `{
		"cmdline":["/opt/datadog-agent/bin/process-agent"], "host":"ubuntu-1404.vagrantup.com", "container_count":0,"container_id":"",
		"system_probe_process_module_enabled":false,
		"docker_socket":"/var/run/docker.sock","forwarder":{"APIKeyStatus":{},"TransactionsCreated":{"RetryQueueSize":0}},"last_collect_time":"2017-09-28 07:10:16","memstats":{"Alloc":2096792,"BuckHashSys":1482366,"BySize":[{"Frees":0,"Mallocs":0,"Size":0},{"Frees":412497,"Mallocs":412634,"Size":8},{"Frees":2158061,"Mallocs":2161254,"Size":16},{"Frees":6301195,"Mallocs":6310794,"Size":32},{"Frees":1025554,"Mallocs":1026617,"Size":48},{"Frees":290415,"Mallocs":291445,"Size":64},{"Frees":67074,"Mallocs":67581,"Size":80},{"Frees":40953,"Mallocs":41171,"Size":96},{"Frees":171019,"Mallocs":171274,"Size":112},{"Frees":174757,"Mallocs":174840,"Size":128},{"Frees":1291,"Mallocs":1324,"Size":144},{"Frees":114113,"Mallocs":114205,"Size":160},{"Frees":45454,"Mallocs":45580,"Size":176},{"Frees":13201,"Mallocs":13208,"Size":192},{"Frees":311938,"Mallocs":311985,"Size":208},{"Frees":3497,"Mallocs":3503,"Size":224},{"Frees":1053,"Mallocs":1058,"Size":240},{"Frees":9967,"Mallocs":10007,"Size":256},{"Frees":937,"Mallocs":987,"Size":288},{"Frees":76158,"Mallocs":76606,"Size":320},{"Frees":1429,"Mallocs":1449,"Size":352},{"Frees":15,"Mallocs":17,"Size":384},{"Frees":48,"Mallocs":183,"Size":416},{"Frees":363,"Mallocs":365,"Size":448},{"Frees":45748,"Mallocs":45751,"Size":480},{"Frees":311959,"Mallocs":311981,"Size":512},{"Frees":46935,"Mallocs":47209,"Size":576},{"Frees":124,"Mallocs":136,"Size":640},{"Frees":31699,"Mallocs":31713,"Size":704},{"Frees":754,"Mallocs":755,"Size":768},{"Frees":106874,"Mallocs":107064,"Size":896},{"Frees":6997,"Mallocs":7045,"Size":1024},{"Frees":60,"Mallocs":68,"Size":1152},{"Frees":69,"Mallocs":83,"Size":1280},{"Frees":1127,"Mallocs":1133,"Size":1408},{"Frees":257413,"Mallocs":257413,"Size":1536},{"Frees":3235,"Mallocs":3245,"Size":1792},{"Frees":3155,"Mallocs":3201,"Size":2048},{"Frees":1069,"Mallocs":1078,"Size":2304},{"Frees":1757,"Mallocs":1774,"Size":2688},{"Frees":692,"Mallocs":692,"Size":3072},{"Frees":350,"Mallocs":352,"Size":3200},{"Frees":0,"Mallocs":5,"Size":3456},{"Frees":6847,"Mallocs":6861,"Size":4096},{"Frees":11,"Mallocs":22,"Size":4864},{"Frees":11,"Mallocs":12,"Size":5376},{"Frees":8,"Mallocs":11,"Size":6144},{"Frees":349,"Mallocs":349,"Size":6528},{"Frees":0,"Mallocs":1,"Size":6784},{"Frees":0,"Mallocs":0,"Size":6912},{"Frees":889,"Mallocs":891,"Size":8192},{"Frees":175,"Mallocs":176,"Size":9472},{"Frees":0,"Mallocs":0,"Size":9728},{"Frees":16,"Mallocs":16,"Size":10240},{"Frees":9,"Mallocs":11,"Size":10880},{"Frees":0,"Mallocs":0,"Size":12288},{"Frees":0,"Mallocs":0,"Size":13568},{"Frees":0,"Mallocs":0,"Size":14336},{"Frees":2,"Mallocs":2,"Size":16384},{"Frees":8,"Mallocs":11,"Size":18432},{"Frees":0,"Mallocs":0,"Size":19072}],"DebugGC":false,"EnableGC":true,"Frees":12980452,"GCCPUFraction":0.00027660329858230417,"GCSys":671744,"HeapAlloc":2096792,"HeapIdle":2113536,"HeapInuse":4243456,"HeapObjects":17826,"HeapReleased":0,"HeapSys":6356992,"LastGC":1506582616117567500,"Lookups":787843,"MCacheInuse":9600,"MCacheSys":16384,"MSpanInuse":85728,"MSpanSys":114688,"Mallocs":12998278,"NextGC":4194304,"NumForcedGC":0,"NumGC":580,"OtherSys":1489530,"PauseEnd":[1506582226101035000,1506582226112501200,1506582236177119200,1506582246109827600,1506582246161165300,1506582256157039800,1506582256196451300,1506582266100831200,1506582266112478200,1506582276101476900,1506582286106396000,1506582286126687500,1506582296099503000,1506582296110266000,1506582306106153200,1506582316097177900,1506582316110753300,1506582326106338000,1506582326122362000,1506582336109635800,1506582346098246400,1506582346111455200,1506582356100117800,1506582356113638400,1506582366106036500,1506582376103559700,1506582376118026000,1506582386103282000,1506582386114026000,1506582396105205200,1506582406101939000,1506582406127845400,1506582416100454100,1506582416111487000,1506582426104607200,1506582436106598000,1506582436121981400,1506582446105687600,1506582446132311000,1506582456104680000,1506582466133406200,1506582466197264000,1506582476123873800,1506582476188246800,1506582486101491500,1506582486113159400,1506582496106409500,1506582506099725000,1506582506115678200,1506582516101830400,1506582516120312600,1506582526133332700,1506582536133508400,1506582536174795500,1506582546101393700,1506582546112282000,1506582556102495500,1506582566097362700,1506582566107364400,1506582576102698000,1506582576113667000,1506582586111737900,1506582596134309400,1506582596154338300,1506582606109634600,1506582606140238800,1506582616100704800,1506582616117567500,1506581106098407200,1506581106109227000,1506581116101760500,1506581116109269000,1506581126107651600,1506581126135905000,1506581136113266200,1506581146101469000,1506581146110897700,1506581156101606000,1506581156112118500,1506581166103714600,1506581176102541300,1506581176115352800,1506581186101816600,1506581186113160200,1506581196102513400,1506581206098444800,1506581206108308700,1506581216099007200,1506581216108940300,1506581226105730800,1506581226126397200,1506581236105284000,1506581246100745200,1506581246109144600,1506581256099923700,1506581256112433700,1506581266104015600,1506581276097864700,1506581276114086700,1506581286143012600,1506581286191402800,1506581296157393200,1506581296262120200,1506581306195998500,1506581316173913000,1506581316257029000,1506581326100242000,1506581326110632400,1506581336106426600,1506581346098762500,1506581346122147800,1506581356171365600,1506581356205906700,1506581366199512300,1506581366274589700,1506581376106299100,1506581376117759500,1506581386104804900,1506581396102094000,1506581396117333000,1506581406101776000,1506581416097738800,1506581416107423000,1506581426099014100,1506581426109568500,1506581436110609700,1506581446098193400,1506581446109034500,1506581456107947800,1506581456122633200,1506581466103874000,1506581476133261300,1506581476160198100,1506581486115513600,1506581486138224400,1506581496116856600,1506581496198111000,1506581506115676000,1506581516100093700,1506581516117489200,1506581526110691000,1506581526122211300,1506581536117504500,1506581546103023600,1506581546122240500,1506581556106510000,1506581566101397200,1506581566117625000,1506581576108421400,1506581576122919200,1506581586113834000,1506581596155364000,1506581596216066600,1506581606105134300,1506581606115653000,1506581616114833700,1506581626101752800,1506581626109803300,1506581636101229300,1506581636117020200,1506581646104537000,1506581656102321400,1506581656110860500,1506581666101982500,1506581676102100700,1506581676111583500,1506581686107026200,1506581686123608300,1506581696107647500,1506581706101321700,1506581706108631300,1506581716100399400,1506581716112764200,1506581726108076500,1506581736103447000,1506581736117864000,1506581746102340600,1506581756099405600,1506581756110430700,1506581766098815200,1506581766108658200,1506581776105958700,1506581786100751000,1506581786109499600,1506581796106018300,1506581796116269600,1506581806111348000,1506581816098433500,1506581816107445500,1506581826102063800,1506581826113313300,1506581836106883800,1506581846098780700,1506581846109101800,1506581856104110600,1506581856115759800,1506581866107832000,1506581876098012200,1506581876107959000,1506581886101321200,1506581886112426200,1506581896105218000,1506581906112097800,1506581906149966600,1506581916147979300,1506581916269657300,1506581926117701000,1506581936101587200,1506581936110430700,1506581946101771000,1506581946111723800,1506581956103544000,1506581966101098800,1506581966110184400,1506581976105113900,1506581976114027300,1506581986155667200,1506581996107511600,1506581996126415400,1506582006102447400,1506582006111234300,1506582016100840200,1506582016111904300,1506582026109052200,1506582036099488300,1506582036109610200,1506582046104646400,1506582056101391000,1506582056109750800,1506582066099548700,1506582066109651700,1506582076157450500,1506582086140934400,1506582086166320000,1506582096106871300,1506582096143585000,1506582106106380800,1506582106134424800,1506582116104113400,1506582126099607600,1506582126110588700,1506582136102966500,1506582146101210400,1506582146142070500,1506582156155882500,1506582156246712600,1506582166157606400,1506582166199486500,1506582176105659400,1506582186097889000,1506582186107386600,1506582196102539300,1506582196111375400,1506582206103425500,1506582216098815700,1506582216122575000],"PauseNs":[202108,111195,21103433,4734207,15843043,17352156,20656960,325707,120873,145645,1259619,165623,206534,201725,678258,94953,164909,278077,411994,4234278,324415,113182,118542,181238,2308665,531144,225488,1524394,203164,1016146,172322,9750220,150765,113357,123909,7350338,129862,1782936,6970455,280722,3123825,8507248,1213709,390248,792984,264343,182112,167632,304755,294682,241455,4768157,11009560,17620970,73196,139842,109420,148579,259885,833279,165886,6578634,2389416,2169273,4134418,1347554,780562,531306,137560,147447,163720,152183,667379,3140549,630481,82678,122852,117171,87366,285812,887783,201820,146584,130057,151639,236975,110644,177687,164236,1106801,4601777,270537,54591,490993,161521,252501,110987,254652,1085837,24134635,5505333,19258429,16958700,25820682,37778785,15691409,337939,211482,178633,144971,2766195,12353022,6834896,44842527,22457655,172082,686213,200130,112915,232162,138353,80799,117007,97286,108548,1937426,280192,156610,99514,430100,155465,687228,2882711,6731693,65804,1624821,159652,285577,60549,157904,5916134,412288,132597,908879,272218,180757,732263,169132,745769,306887,7252246,4394707,951611,82203,213042,117441,112781,112222,300525,1211909,145623,113760,164115,225506,96600,953395,1874155,204582,115017,187433,130060,156279,312904,97728,2302220,232036,124466,632575,121143,149310,200161,248362,153779,119662,494180,534981,316531,185806,152670,211013,132662,2033315,253769,850340,299891,140935,120561,170304,87502,712511,758267,102834,472697,1307030,24962796,254714,2628369,266971,1318833,108503,131614,120129,222602,1789785,129309,746252,19088113,823822,253070,163050,183856,123350,126196,226394,97382,152971,1404152,196053,1299475,136466,185384,20561432,12951037,1264979,5630592,2187745,254259,1811039,164578,144580,244778,207351,2194256,12554634,16700526,5939874,18788363,9003636,379686,92515,771011,1034056,795588,842805,313889,553591],"PauseTotalNs":833945600,"StackInuse":983040,"StackSys":983040,"Sys":11114744,"TotalAlloc":1301199968},"pid":485,"process_count":84,"queue_size":0,"splitter":{},"uptime":3464,"version":{"Major": 0,"Minor": 99,"Patch": 0},"log_file":"/var/log/datadog/process-agent.log"
				}`
)

type testServerHandler struct {
	t *testing.T
}

func (h *testServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case expVarPath:
		h.t.Logf("serving fake info data for %s", r.URL.Path)
		_, err := w.Write([]byte(expVarResponse))
		if err != nil {
			h.t.Errorf("error serving %s: %v", r.URL, err)
		}
	case sysProbeProcessModuleEnabledExpVarPath:
		// serve same information as above, except that system probe config flag is enabled
		h.t.Logf("serving fake info data for %s", r.URL.Path)
		sysProbeEnabledResponse := strings.ReplaceAll(expVarResponse, `"system_probe_process_module_enabled":false`, `"system_probe_process_module_enabled":true`)
		_, err := w.Write([]byte(sysProbeEnabledResponse))
		if err != nil {
			h.t.Errorf("error serving %s: %v", r.URL, err)
		}
	default:
		h.t.Logf("answering 404 for %s", r.URL)
		w.WriteHeader(http.StatusNotFound)
	}
}

func testServer(t *testing.T) *httptest.Server {
	server := httptest.NewServer(&testServerHandler{t: t})
	t.Logf("test server with valid data listening on %s", server.URL)
	return server
}

func setAgentVersionForTest(newVersion string) func() {
	oldVersion := version.AgentVersion
	version.AgentVersion = newVersion
	return func() {
		version.AgentVersion = oldVersion
	}
}

func TestInfo(t *testing.T) {
	reset := setAgentVersionForTest("0.99.0")
	defer reset()

	assert := assert.New(t)
	server := testServer(t)
	assert.NotNil(server)
	defer server.Close()

	err := initInfo("ubuntu-1404.vagrantup.com")
	assert.NoError(err)
	var buf bytes.Buffer
	err = Info(&buf, server.URL+expVarPath)
	assert.NoError(err)
	info := buf.String()
	assert.Equal(expectedInfo, info)

	// check that if system probe process module config flag is disabled,
	// it is displayed correctly in info command output
	buf.Reset() // empty the buffer before reusing
	err = Info(&buf, server.URL+sysProbeProcessModuleEnabledExpVarPath)
	assert.NoError(err)
	info = buf.String()
	sysProbeProcessModuleEnabledExpectedInfo := strings.ReplaceAll(expectedInfo,
		"System Probe Process Module Status: Not running",
		"System Probe Process Module Status: Running")
	assert.Equal(sysProbeProcessModuleEnabledExpectedInfo, info)
}

func TestNotRunning(t *testing.T) {
	reset := setAgentVersionForTest("0.99.0")
	defer reset()

	assert := assert.New(t)
	server := testServer(t)
	assert.NotNil(server)
	defer server.Close()

	err := initInfo("host")
	assert.NoError(err)
	var buf bytes.Buffer
	// we are going to use a different port so we got
	// connection refused response, which is equal to
	// agent is not running
	url, err := url.Parse(server.URL)
	assert.NoError(err)
	hostPort := strings.Split(url.Host, ":")
	port, err := strconv.Atoi(hostPort[1])
	assert.NoError(err)
	newURL := "http://" + hostPort[0] + ":" + strconv.Itoa(port+1)

	err = Info(&buf, newURL)
	assert.Error(err)
	info := buf.String()
	assert.Equal(notRunningInfo, info)
}

func TestError(t *testing.T) {
	reset := setAgentVersionForTest("0.99.0")
	defer reset()

	assert := assert.New(t)
	server := testServer(t)
	assert.NotNil(server)
	defer server.Close()

	err := initInfo("host")
	assert.NoError(err)
	var buf bytes.Buffer
	// same port but a 404 response
	err = Info(&buf, server.URL+"/haha")
	assert.Error(err)
	info := buf.String()

	assert.Equal(errInfo, info)
}
