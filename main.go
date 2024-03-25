package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nitram509/gofitz/pkg/soap"
	"github.com/nitram509/gofitz/pkg/tr064/lan"
	"github.com/nitram509/gofitz/pkg/tr064model"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

const namespace = "fbhosts"

var (
	metricTook = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "refresh",
		Name:      "duration_seconds",
	}, []string{"box"})
	metricTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "refresh",
		Name:      "attempts_total",
	}, []string{"box"})
	metricFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "refresh",
		Name:      "failed_total",
	}, []string{"box"})
	metricInterval = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "refresh",
		Name:      "interval_seconds",
	})
	metricCurrent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "hosts",
		Name:      "current",
	}, []string{"box"})
	metricLast = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "hosts",
		Name:      "last_updated_seconds",
	}, []string{"box"})
)

type Config struct {
	file string `json:"-"`
	addr string `json:"-"`

	Boxes    []Box         `json:"boxes"`
	Interval time.Duration `json:"interval"`
}

type Box struct {
	Address  string `json:"address"`
	User     string `json:"user"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

func main() {
	file := flag.String("config", "boxes.yaml", "yaml config file")
	out := flag.String("out", "hosts", "hosts file to write")
	addr := flag.String("http", ":4949", "http address to listen on")
	flag.Parse()

	cfg, err := parse(*file, *out, *addr)
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	if err := run(ctx, cfg); err != nil {
		log.Fatalln(err)
	}
}

func parse(file, out, addr string) (Config, error) {
	var (
		cfg Config
		err error
	)

	cfg.addr = addr
	cfg.file, err = filepath.Abs(out)
	if err != nil {
		return cfg, err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return cfg, err
	}

	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

func run(ctx context.Context, cfg Config) error {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("http: listening on", cfg.addr)
		if err := http.ListenAndServe(cfg.addr, nil); err != nil {
			log.Printf("http: %s", err)
		}
	}()

	entries := make(map[string][]Host)
	for _, box := range cfg.Boxes {
		entries[box.Address] = nil
	}

	t := time.NewTicker(cfg.Interval)
	metricInterval.Set(float64(cfg.Interval.Seconds()))

	boxes := make([]string, len(cfg.Boxes))
	for i, box := range cfg.Boxes {
		boxes[i] = box.Address
	}

	log.Printf("hosts: writing to %s", cfg.file)
	log.Printf("refresh: polling [%s] every %s", strings.Join(boxes, ","), cfg.Interval)
	for {
		f, err := os.Create(cfg.file)
		if err != nil {
			return err
		}

		for _, box := range cfg.Boxes {
			labels := prometheus.Labels{"box": box.Address}

			metricTotal.With(labels).Inc()
			start := time.Now()
			list, err := hosts(box)
			if err != nil {
				metricFailed.With(labels).Inc()
				log.Printf("error: box %s: %s", box.Address, err)
				continue
			}
			entries[box.Address] = list
			metricTook.With(labels).Observe(float64(time.Since(start).Seconds()))
			metricLast.With(labels).Set(float64(time.Now().Unix()))
			metricCurrent.With(labels).Set(float64(len(entries[box.Address])))

			fmt.Fprintf(f, "# fritzbox %s\n", box.Address)
			for _, host := range entries[box.Address] {
				fmt.Fprintln(f, host.String())
			}
		}

		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
}

type Host struct {
	*tr064model.XAvmGetHostListResponse
	domain string
}

func (h Host) String() string {
	return fmt.Sprintf("%s\t%s %s.%s", h.IPAddress, h.HostName, h.HostName, h.domain)
}

var (
	exprMac = regexp.MustCompile(`PC(-[A-Z0-9]{1,2}){6}`)
	exprIp4 = regexp.MustCompile(`PC(-\d{1,3}){4}`)
	exprIp6 = regexp.MustCompile(`PC(-[a-z0-9]{0,4}){6}`)
)

func hosts(box Box) ([]Host, error) {
	session := soap.NewSession(box.Address, box.User, box.Password)
	list, err := lan.XAvmGetHostList(session)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]*tr064model.XAvmGetHostListResponse)
	for i, host := range list {
		name := host.HostName
		other, ok := seen[name]

		switch {
		case name == "fritz.box":
		case ok && other.Active:
		case exprMac.MatchString(name):
		case exprIp4.MatchString(name):
		case exprIp6.MatchString(name):
		default:
			seen[name] = &list[i]
		}
	}

	hosts := make([]Host, 0, len(seen))
	for _, host := range seen {
		hosts = append(hosts, Host{XAvmGetHostListResponse: host, domain: box.Domain})
	}
	return hosts, nil
}
