package agent

import (
	"encoding/json"
	"io"
	"mui/internal/shared"
	"os"
	"time"
)

func writeForwardConnections(path string, points []shared.ForwardConnectionPoint) error {
	raw, err := json.Marshal(points)
	if err != nil {
		return err
	}
	if err = os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func readForwardConnections() []shared.ForwardConnectionPoint {
	f, err := os.Open(ForwardConnections)
	if err != nil {
		return nil
	}
	defer f.Close()
	var points []shared.ForwardConnectionPoint
	if json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&points) != nil {
		return nil
	}
	out := make([]shared.ForwardConnectionPoint, 0, 500)
	now := time.Now()
	for _, p := range points {
		if !p.At.IsZero() && now.Sub(p.At) <= 2*time.Minute && p.At.Sub(now) < time.Minute {
			out = append(out, p)
			if len(out) == 500 {
				break
			}
		}
	}
	return out
}
