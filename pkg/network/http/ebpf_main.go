// +build linux_bpf

package http

import (
	"math"
	"os"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

const (
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the accept syscall).
	maxActive                = 128
	defaultClosedChannelSize = 500
)

var mainHTTPMaps = []string{
	string(probes.HttpInFlightMap),
	string(probes.HttpBatchesMap),
	string(probes.HttpBatchStateMap),

	// SSL
	"sock_by_pid_fd",
	"ssl_sock_by_ctx",
	"ssl_read_args",
	"fd_by_ssl_bio",

	// Crypto (BIO)
	"bio_new_socket_args",
}

type subprogram interface {
	Start() error
	Init() error
	Close() error
}

type ebpfProgram struct {
	*manager.Manager
	cfg         *config.Config
	perfHandler *ddebpf.PerfHandler
	bytecode    bytecode.AssetReader
	subprograms []subprogram
	sockFDMap   *ebpf.Map
}

func newEBPFProgram(c *config.Config, offsets []manager.ConstantEditor, sockFD *ebpf.Map) (*ebpfProgram, error) {
	bytecode, err := netebpf.ReadHTTPModule(c.BPFDir, c.BPFDebug)
	if err != nil {
		return nil, err
	}

	closedChannelSize := defaultClosedChannelSize
	if c.ClosedChannelSize > 0 {
		closedChannelSize = c.ClosedChannelSize
	}
	perfHandler := ddebpf.NewPerfHandler(closedChannelSize)

	mgr := &manager.Manager{
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: string(probes.HttpNotificationsMap)},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        perfHandler.DataHandler,
					LostHandler:        perfHandler.LostHandler,
				},
			},
		},
		Probes: []*manager.Probe{
			{Section: string(probes.TCPSendMsgReturn), KProbeMaxActive: maxActive},
			{Section: string(probes.SocketHTTPFilter)},
		},
	}

	for _, m := range mainHTTPMaps {
		mgr.Maps = append(mgr.Maps, &manager.Map{Name: m})
	}

	program := &ebpfProgram{
		Manager:     mgr,
		perfHandler: perfHandler,
		bytecode:    bytecode,
		cfg:         c,
		sockFDMap:   sockFD,
	}

	sharedLibraries := findOpenSSLLibraries(c.ProcRoot)
	var subprograms []subprogram
	subprograms = append(subprograms, createSSLPrograms(program, offsets, sharedLibraries)...)
	subprograms = append(subprograms, createCryptoPrograms(program, sharedLibraries)...)
	program.subprograms = subprograms

	return program, nil
}

func (e *ebpfProgram) Init() error {
	options := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			string(probes.HttpInFlightMap): {
				Type:       ebpf.Hash,
				MaxEntries: uint32(e.cfg.MaxTrackedConnections),
				EditorFlag: manager.EditMaxEntries,
			},
			"ssl_sock_by_ctx": {
				Type:       ebpf.Hash,
				MaxEntries: uint32(e.cfg.MaxTrackedConnections),
				EditorFlag: manager.EditMaxEntries,
			},
		},
		ActivatedProbes: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: string(probes.SocketHTTPFilter),
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: string(probes.TCPSendMsgReturn),
				},
			},
		},
	}

	if e.sockFDMap != nil {
		options.MapEditors = map[string]*ebpf.Map{
			"sock_by_pid_fd": e.sockFDMap,
		}
	}

	err := e.InitWithOptions(e.bytecode, options)
	if err != nil {
		return err
	}

	for _, subprogram := range e.subprograms {
		err := subprogram.Init()
		if err != nil {
			log.Errorf("error initializing http subprogram: %s. ignoring it.", err)
		}
	}

	return nil
}

func (e *ebpfProgram) Start() error {
	err := e.Manager.Start()
	if err != nil {
		return err
	}

	for _, subprogram := range e.subprograms {
		err := subprogram.Start()
		if err != nil {
			log.Errorf("error starting http subprogram: %s. ignoring it.", err)
		}
	}

	return nil
}

func (e *ebpfProgram) Close() error {
	for _, p := range e.subprograms {
		p.Close()
	}

	return e.Manager.Stop(manager.CleanAll)
}

func setupSharedMaps(mainProgram *ebpfProgram, toShare ...string) map[string]*ebpf.Map {
	if mainProgram == nil || len(toShare) == 0 {
		return nil
	}

	sharedMaps := make(map[string]*ebpf.Map)
	for _, m := range toShare {
		emap, _, _ := mainProgram.GetMap(m)
		if emap == nil {
			log.Errorf("couldn't retrieve map: %s", m)
			continue
		}
		sharedMaps[m] = emap
	}

	return sharedMaps
}
