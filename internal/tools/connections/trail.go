package connections

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
)

// trailLogFormatQuery returns the query values requesting the JSONL trail-log
// format, which yields newline-delimited JSON events.
func trailLogFormatQuery() url.Values {
	return url.Values{"format": []string{"jsonl"}}
}

// The PrivX connection-manager returns the audited trail (with its channels)
// as part of a single connection object, but the Go SDK's
// connectionmanager.Connection struct does not model the `trail` field. These
// types mirror the documented trail schema so channels can be read from the raw
// connection JSON.
//
// See https://privx.docs.ssh.com/api/connection-manager/schemas/trail

// Trail is the audited trail metadata of a connection.
type Trail struct {
	ConnectionID string         `json:"connection_id,omitempty"`
	HostID       string         `json:"host_id,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	Protocol     string         `json:"protocol,omitempty"`
	Channels     []TrailChannel `json:"channels,omitempty"`
}

// TrailChannel is one channel within an audited connection trail.
type TrailChannel struct {
	ID                  string            `json:"id,omitempty"`
	Type                string            `json:"type,omitempty"`
	BytesClientToServer int64             `json:"bytes_client_to_server,omitempty"`
	BytesServerToClient int64             `json:"bytes_server_to_client,omitempty"`
	ProtocolFile        TrailProtocolFile `json:"protocol_file,omitempty"`
}

// TrailProtocolFile describes the stored trail-log file for a channel.
type TrailProtocolFile struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Closed bool   `json:"closed,omitempty"`
	Status string `json:"status,omitempty"`
}

// connectionTrailEnvelope is used to pull the `trail` field out of the raw
// connection JSON that the typed SDK struct discards.
type connectionTrailEnvelope struct {
	Trail Trail `json:"trail"`
}

// TrailChannelsFromConnectionJSON extracts the trail channels from the raw JSON
// bytes of a single connection response. The typed SDK struct drops the trail
// field, so the raw connection JSON is the only source of channel IDs.
func TrailChannelsFromConnectionJSON(raw []byte) ([]TrailChannel, error) {
	var env connectionTrailEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode connection trail: %w", err)
	}

	return env.Trail.Channels, nil
}

// fetchConnectionJSON fetches the raw JSON bytes of a single connection,
// preserving the `trail` field that the typed SDK struct drops.
func fetchConnectionJSON(connector restapi.Connector, connID string) ([]byte, error) {
	body, err := connector.
		URL("/connection-manager/api/v1/connections/%s", connID).
		Query(url.Values{"verbose": []string{"true"}}).
		Fetch()
	if err != nil {
		return nil, fmt.Errorf("fetch connection: %w", err)
	}

	return body, nil
}

// CollectTrailCommands downloads and parses the trail logs for the given
// channels, returning the reconstructed commands in channel order. Channels
// with an unclean close are skipped (their logs are unreliable), matching the
// PrivX Python SDK example.
func CollectTrailCommands(connector restapi.Connector, connID string, channels []TrailChannel) ([]TrailCommand, error) {
	var all []TrailCommand

	for _, ch := range channels {
		if ch.ProtocolFile.Status == "UNCLEAN_CLOSE" {
			continue
		}

		log, err := fetchTrailLog(connector, connID, ch.ID)
		if err != nil {
			return nil, fmt.Errorf("channel %s: %w", ch.ID, err)
		}

		all = append(all, parseTrailLog(ch.ID, ch.Type, log)...)
	}

	return all, nil
}

// DiscoverTrailChannels fetches the connection's raw JSON and returns its trail
// channels. When channelID is non-empty, only that channel is returned (if it
// exists), supporting callers that target a single channel.
func DiscoverTrailChannels(connector restapi.Connector, connID, channelID string) ([]TrailChannel, error) {
	raw, err := fetchConnectionJSON(connector, connID)
	if err != nil {
		return nil, err
	}

	channels, err := TrailChannelsFromConnectionJSON(raw)
	if err != nil {
		return nil, err
	}

	if channelID == "" {
		return channels, nil
	}

	for _, ch := range channels {
		if ch.ID == channelID {
			return []TrailChannel{ch}, nil
		}
	}

	return nil, fmt.Errorf("channel %s not found in connection trail", channelID)
}

// FormatTrailCommandItems converts reconstructed trail commands to compact maps.
func FormatTrailCommandItems(cmds []TrailCommand) []map[string]any {
	out := make([]map[string]any, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, map[string]any{
			"channel_id": c.ChannelID,
			"type":       c.ChannelType,
			"timestamp":  c.Timestamp,
			"command":    c.Command,
		})
	}

	return out
}

// trailLogEvent is one newline-delimited JSON event in a downloaded trail log.
// Shell input is carried on stdin events whose data is base64-encoded; exec
// channels carry the executed command directly.
type trailLogEvent struct {
	Type    string `json:"type"`
	TS      string `json:"ts"`
	Data    string `json:"data"`
	Command string `json:"command"`
}

// TrailCommand is one reconstructed command/content entry from a channel trail.
type TrailCommand struct {
	ChannelID   string
	ChannelType string
	Timestamp   string
	Command     string
}

// fetchTrailLog downloads the raw JSONL trail log for a single channel into
// memory. It bypasses the SDK's DownloadTrailLog (which writes to a file) by
// using the connector's Fetch, so the bytes can be parsed directly.
func fetchTrailLog(connector restapi.Connector, connID, chanID string) ([]byte, error) {
	session, err := connectionmanager.New(connector).CreateSessionForTrailLogDownload(connID, chanID)
	if err != nil {
		return nil, fmt.Errorf("create trail-log session: %w", err)
	}

	body, err := connector.
		URL("/connection-manager/api/v1/connections/%s/channel/%s/log/%s", connID, chanID, session.SessionID).
		Query(trailLogFormatQuery()).
		Fetch()
	if err != nil {
		return nil, fmt.Errorf("download trail log: %w", err)
	}

	return body, nil
}

// parseTrailLog reconstructs commands from a channel's JSONL trail log, mirroring
// the PrivX Python SDK example: stdin events are base64-decoded and grouped into
// a command on each carriage return; exec events contribute their command field.
func parseTrailLog(chanID, chanType string, log []byte) []TrailCommand {
	var commands []TrailCommand

	var (
		buf     strings.Builder
		startTS string
	)

	for _, line := range strings.Split(string(log), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		var ev trailLogEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}

		switch ev.Type {
		case "exec":
			if ev.Command != "" {
				commands = append(commands, TrailCommand{
					ChannelID:   chanID,
					ChannelType: chanType,
					Timestamp:   trimTS(ev.TS),
					Command:     ev.Command,
				})
			}
		case "stdin":
			decoded, err := base64.StdEncoding.DecodeString(ev.Data)
			if err != nil {
				continue
			}

			for _, r := range string(decoded) {
				if r == '\r' || r == '\n' {
					cmd := strings.TrimSpace(buf.String())
					if cmd != "" {
						commands = append(commands, TrailCommand{
							ChannelID:   chanID,
							ChannelType: chanType,
							Timestamp:   startTS,
							Command:     cmd,
						})
					}

					buf.Reset()
					startTS = ""

					continue
				}

				if buf.Len() == 0 {
					startTS = trimTS(ev.TS)
				}

				buf.WriteRune(r)
			}
		}
	}

	return commands
}

// trimTS trims a timestamp to seconds precision (first 19 chars of RFC3339),
// matching the Python example's ts[0:19].
func trimTS(ts string) string {
	if len(ts) >= 19 {
		return ts[:19]
	}

	return ts
}
