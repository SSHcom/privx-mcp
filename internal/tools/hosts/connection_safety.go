package hosts

import (
	"fmt"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
)

// connectionCheckWindow is how far back host-delete looks for active
// connections that would make a deletion unsafe.
const connectionCheckWindow = 24 * time.Hour

// AssertNoActiveConnections walks the connection history for hostID (sorted
// by `connected` descending) and returns an error if any connection whose
// `connected` timestamp falls within the last 24 hours has no `disconnected`
// timestamp. Connections older than the window are ignored; because results
// are sorted by `connected` DESC, the first connection older than the cutoff
// lets us stop paging.
func AssertNoActiveConnections(client *connectionmanager.ConnectionManager, hostID string) error {
	cutoff := time.Now().UTC().Add(-connectionCheckWindow)

	const pageSize = 100

	const maxPages = 100 // safety cap against misbehaving pagination

	for page := 0; page < maxPages; page++ {
		offset := page * pageSize
		search := &connectionmanager.ConnectionSearch{
			TargetHost: []string{hostID},
		}
		opts := []filters.Option{
			filters.Paging(offset, pageSize),
			filters.Sort("connected", "DESC"),
		}

		result, err := client.SearchConnections(search, opts...)
		if err != nil {
			return fmt.Errorf("failed to fetch connections for host %s: %w", hostID, err)
		}

		if len(result.Items) == 0 {
			return nil
		}

		for _, conn := range result.Items {
			connected, ok := parseConnectionTime(conn.Connected)
			if !ok {
				// No usable `connected` timestamp: cannot place this
				// connection inside the 24h window, so it does not block.
				continue
			}

			if connected.Before(cutoff) {
				// Sorted by `connected` DESC: everything after this is
				// older than the window, so we are done.
				return nil
			}

			if conn.Disconnected == "" {
				return fmt.Errorf(
					"refusing to delete host %s: connection %s started at %s (within the last 24 hours) and is not disconnected",
					hostID, conn.ID, conn.Connected,
				)
			}
		}

		if len(result.Items) < pageSize {
			return nil
		}
	}

	return nil
}

// parseConnectionTime parses a PrivX connection timestamp string (the
// `connected`/`disconnected` fields) into a UTC time.Time. Returns ok=false
// when the value is empty or cannot be parsed.
func parseConnectionTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}

	for _, layout := range connectionTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}

	return time.Time{}, false
}

// connectionTimeLayouts are the timestamp layouts PrivX may use for
// connection `connected`/`disconnected` fields, tried in order.
var connectionTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999Z",
	"2006-01-02T15:04:05Z",
}
