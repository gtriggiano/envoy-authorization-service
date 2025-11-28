package ip_match_database

import (
	"context"
)

// DataSource abstracts the external data store for IP address lookups
type DataSource interface {
	// Contains checks if the IP address exists in the data source
	// Returns true if the IP is found, false otherwise
	// Returns an error if the query fails or times out
	Contains(ctx context.Context, ipAddress string) (bool, error)

	// Close releases resources held by the data source
	Close() error

	// HealthCheck verifies connectivity to the data source
	// Returns an error if the data source is unreachable
	HealthCheck(ctx context.Context) error
}
