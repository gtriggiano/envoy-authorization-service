package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// filteringGatherer wraps another Gatherer and drops metric families with specified prefixes.
type filteringGatherer struct {
	inner        prometheus.Gatherer
	dropPrefixes []string
}

func (f filteringGatherer) Gather() ([]*io_prometheus_client.MetricFamily, error) {
	mfs, err := f.inner.Gather()
	if err != nil {
		return nil, err
	}
	out := make([]*io_prometheus_client.MetricFamily, 0, len(mfs))
outer:
	for _, mf := range mfs {
		name := mf.GetName()
		for _, p := range f.dropPrefixes {
			if strings.HasPrefix(name, p) {
				continue outer
			}
		}
		out = append(out, mf)
	}
	return out, nil
}
