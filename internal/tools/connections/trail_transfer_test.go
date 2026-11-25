package connections

import (
	"fmt"
	"testing"
)

func TestTransferDirection(t *testing.T) {
	cases := map[int]string{
		1:  "download",
		2:  "upload",
		0:  "unknown",
		3:  "unknown",
		-1: "unknown",
	}

	for direction, want := range cases {
		if got := TransferDirection(direction); got != want {
			t.Errorf("TransferDirection(%d) = %q, want %q", direction, got, want)
		}
	}
}

func TestFormatTransferredFiles_Download(t *testing.T) {
	items, total := FormatTransferredFiles([]TrailChannel{{
		ID:   "7",
		Type: "scp",
		TransferredFiles: []TrailTransferredFile{
			{Name: "/etc/hosts", Direction: 1, PayloadSize: 120, Status: "OK"},
		},
	}})

	if total != 1 || len(items) != 1 {
		t.Fatalf("total=%d items=%v", total, items)
	}

	if items[0]["direction"] != "download" || items[0]["channel_type"] != "scp" {
		t.Errorf("item = %v", items[0])
	}
}

func TestFormatTransferredFiles_NoFilesIsEmptyNotNil(t *testing.T) {
	items, total := FormatTransferredFiles([]TrailChannel{{ID: "0", Type: "shell"}})

	if items == nil || len(items) != 0 || total != 0 {
		t.Fatalf("items=%v total=%d, want empty non-nil list and zero", items, total)
	}
}

func TestFormatTransferredFiles_CapsListButKeepsTotal(t *testing.T) {
	files := make([]TrailTransferredFile, MaxTrailTransferredFiles+25)
	for i := range files {
		files[i] = TrailTransferredFile{Name: fmt.Sprintf("/f%d", i), Direction: 2}
	}

	items, total := FormatTransferredFiles([]TrailChannel{{ID: "1", Type: "sftp", TransferredFiles: files}})

	if len(items) != MaxTrailTransferredFiles {
		t.Errorf("listed %d files, want cap %d", len(items), MaxTrailTransferredFiles)
	}

	if total != MaxTrailTransferredFiles+25 {
		t.Errorf("total = %d, want %d", total, MaxTrailTransferredFiles+25)
	}
}

func TestTrailChannelsFromConnectionJSON_ParsesTransfers(t *testing.T) {
	raw := []byte(`{"trail":{"channels":[{"id":"1","type":"sftp",
		"protocol_file":{"status":"OK","open_time":"t0","close_time":"t1"},
		"transferred_files":[{"name":"/a","direction":2,"payload_size":10,"status":"OK"}],
		"bytes_client_to_server":47}]}}`)

	channels, err := TrailChannelsFromConnectionJSON(raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(channels) != 1 || len(channels[0].TransferredFiles) != 1 {
		t.Fatalf("channels = %+v", channels)
	}

	if f := channels[0].TransferredFiles[0]; f.Name != "/a" || f.Direction != 2 || f.PayloadSize != 10 {
		t.Errorf("file = %+v", f)
	}

	if channels[0].ProtocolFile.OpenTime != "t0" || channels[0].ProtocolFile.CloseTime != "t1" {
		t.Errorf("protocol file times = %+v", channels[0].ProtocolFile)
	}
}
