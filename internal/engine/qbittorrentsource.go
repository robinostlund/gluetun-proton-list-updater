package engine

import (
	"context"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/qbittorrent"
)

// qbittorrentSource reads rates from a qBittorrent Web API.
//
// The conversion to the canonical unit happens here and nowhere else: qBittorrent reports
// bytes per second, everything downstream works in bits.
//
// It also keeps the last raw reading, because qBittorrent answers more than rates - the
// session byte counters, the peer connection state - and those are qBittorrent's own facts
// rather than something every source could provide.
type qbittorrentSource struct {
	client *qbittorrent.Client
	// last is the raw response from the most recent successful read.
	last qbittorrent.Transfer
}

func (s *qbittorrentSource) name() string { return "qbittorrent" }

func (s *qbittorrentSource) read(ctx context.Context) (reading rateReading, err error) {
	transfer, err := s.client.Transfer(ctx)
	if err != nil {
		return rateReading{}, err
	}
	s.last = transfer
	return rateReading{
		Download:        bitsFromBytes(transfer.DownloadSpeed),
		Upload:          bitsFromBytes(transfer.UploadSpeed),
		DownloadedBytes: transfer.DownloadTotal,
		UploadedBytes:   transfer.UploadTotal,
	}, nil
}
