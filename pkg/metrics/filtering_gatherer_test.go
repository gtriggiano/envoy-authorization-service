package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestFilteringGatherer_Gather(t *testing.T) {
	// Create a test registry with some metrics
	reg := prometheus.NewRegistry()

	// Register some test metrics
	counter1 := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter_one",
		Help: "Test counter one",
	})
	counter2 := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "keep_counter_two",
		Help: "Test counter two",
	})
	counter3 := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter_three",
		Help: "Test counter three",
	})

	reg.MustRegister(counter1, counter2, counter3)

	// Increment counters to ensure they appear in gather
	counter1.Inc()
	counter2.Inc()
	counter3.Inc()

	t.Run("filters metrics with specified prefixes", func(t *testing.T) {
		fg := filteringGatherer{
			inner:        reg,
			dropPrefixes: []string{"test_"},
		}

		mfs, err := fg.Gather()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should only have keep_counter_two
		if len(mfs) != 1 {
			t.Errorf("expected 1 metric family, got %d", len(mfs))
		}

		if len(mfs) > 0 && mfs[0].GetName() != "keep_counter_two" {
			t.Errorf("expected metric name 'keep_counter_two', got '%s'", mfs[0].GetName())
		}
	})

	t.Run("filters multiple prefixes", func(t *testing.T) {
		fg := filteringGatherer{
			inner:        reg,
			dropPrefixes: []string{"test_", "keep_"},
		}

		mfs, err := fg.Gather()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have no metrics
		if len(mfs) != 0 {
			t.Errorf("expected 0 metric families, got %d", len(mfs))
		}
	})

	t.Run("no filtering with empty prefixes", func(t *testing.T) {
		fg := filteringGatherer{
			inner:        reg,
			dropPrefixes: []string{},
		}

		mfs, err := fg.Gather()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have all 3 metrics
		if len(mfs) != 3 {
			t.Errorf("expected 3 metric families, got %d", len(mfs))
		}
	})

	t.Run("propagates gather errors", func(t *testing.T) {
		testErr := errors.New("test error")
		errorGatherer := &errorMockGatherer{err: testErr}
		fg := filteringGatherer{
			inner:        errorGatherer,
			dropPrefixes: []string{"test_"},
		}

		_, err := fg.Gather()
		if err == nil {
			t.Error("expected error to be propagated")
		}
		if err != testErr {
			t.Errorf("expected test error, got %v", err)
		}
	})
}

// errorMockGatherer is a mock gatherer that returns an error
type errorMockGatherer struct {
	err error
}

func (e *errorMockGatherer) Gather() ([]*io_prometheus_client.MetricFamily, error) {
	return nil, e.err
}
