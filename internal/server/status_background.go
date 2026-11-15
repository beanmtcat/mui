package server

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	statusBackgroundAssetKey     = "background"
	maxStatusBackgroundBytes     = 3 << 20
	maxStatusBackgroundDimension = 6000
)

type statusAsset struct {
	Mime      string
	Data      []byte
	ETag      string
	UpdatedMs int64
}

func (s *Store) StatusAsset(key string) (*statusAsset, error) {
	s.statusAssetReads.Add(1)
	var asset statusAsset
	var data []byte
	err := s.DB.QueryRow(
		`SELECT mime, data, etag, updated_ms FROM mui_status_assets WHERE key=$1`,
		key,
	).Scan(&asset.Mime, &data, &asset.ETag, &asset.UpdatedMs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	asset.Data = append([]byte(nil), data...)
	return &asset, nil
}

func (s *Store) PutStatusAsset(key, mime string, data []byte, etag string, updatedMs int64) error {
	_, err := s.DB.Exec(
		`INSERT INTO mui_status_assets(key,mime,data,etag,updated_ms) VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT(key) DO UPDATE SET mime=excluded.mime, data=excluded.data, etag=excluded.etag, updated_ms=excluded.updated_ms`,
		key, mime, data, etag, updatedMs,
	)
	return err
}

func (s *Store) DeleteStatusAsset(key string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_status_assets WHERE key=$1`, key)
	return err
}

func (a *App) cachedStatusBackground() (*statusAsset, error) {
	a.statusCacheMu.RLock()
	if a.statusBgLoaded {
		bg := a.statusBg
		a.statusCacheMu.RUnlock()
		return bg, nil
	}
	gen := a.statusCacheGen
	a.statusCacheMu.RUnlock()

	bg, err := a.Store.StatusAsset(statusBackgroundAssetKey)
	if err != nil {
		return nil, err
	}

	a.statusCacheMu.Lock()
	if !a.statusBgLoaded && a.statusCacheGen == gen {
		a.statusBg = bg
		a.statusBgLoaded = true
	} else if a.statusBgLoaded {
		bg = a.statusBg
	}
	a.statusCacheMu.Unlock()
	return bg, nil
}

func (a *App) statusPageBackground(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		bg, err := a.cachedStatusBackground()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if bg == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "private, no-cache")
		w.Header().Set("ETag", `"`+bg.ETag+`"`)
		if ifNoneMatchMatches(r.Header.Values("If-None-Match"), bg.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", bg.Mime)
		w.Header().Set("Content-Length", strconv.Itoa(len(bg.Data)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(bg.Data)
		}
		return

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxStatusBackgroundBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				errorJSON(w, http.StatusRequestEntityTooLarge, "背景图片不能超过 3 MiB")
				return
			}
			errorJSON(w, http.StatusBadRequest, "读取图片请求失败")
			return
		}
		mime, width, height, err := validateStatusBackgroundImage(raw)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		sum := sha256.Sum256(raw)
		etag := hex.EncodeToString(sum[:16])
		nowMs := time.Now().UnixMilli()
		if err := a.Store.PutStatusAsset(statusBackgroundAssetKey, mime, raw, etag, nowMs); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}

		cachedCopy := append([]byte(nil), raw...)
		a.statusCacheMu.Lock()
		a.statusCacheGen++
		a.statusBg = &statusAsset{
			Mime:      mime,
			Data:      cachedCopy,
			ETag:      etag,
			UpdatedMs: nowMs,
		}
		a.statusBgLoaded = true
		a.statusSnapshotBody = nil
		a.statusSnapshotExpires = time.Time{}
		a.statusCDNBody = nil
		a.statusCDNExpires = time.Time{}
		a.statusCacheMu.Unlock()

		a.auditRequest(r, "settings.status_background", "status_page", fmt.Sprintf("upload mime=%s size=%d %dx%d", mime, len(raw), width, height))
		writeJSON(w, 200, map[string]any{
			"ok":                true,
			"backgroundSet":     true,
			"backgroundVersion": etag,
		})
		return

	case http.MethodDelete:
		if err := a.Store.DeleteStatusAsset(statusBackgroundAssetKey); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.statusCacheMu.Lock()
		a.statusCacheGen++
		a.statusBg = nil
		a.statusBgLoaded = true
		a.statusSnapshotBody = nil
		a.statusSnapshotExpires = time.Time{}
		a.statusCDNBody = nil
		a.statusCDNExpires = time.Time{}
		a.statusCacheMu.Unlock()

		a.auditRequest(r, "settings.status_background", "status_page", "delete")
		writeJSON(w, 200, map[string]any{
			"ok":                true,
			"backgroundSet":     false,
			"backgroundVersion": "",
		})
		return

	default:
		http.NotFound(w, r)
	}
}

func (a *App) publicBackground(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkPublicStatusGate(w, r); !ok {
		return
	}
	bg, err := a.cachedStatusBackground()
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	if bg == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", `"`+bg.ETag+`"`)
	if ifNoneMatchMatches(r.Header.Values("If-None-Match"), bg.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", bg.Mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(bg.Data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(bg.Data)
	}
}

func ifNoneMatchMatches(headers []string, etag string) bool {
	if etag == "" || len(headers) == 0 {
		return false
	}
	for _, header := range headers {
		for _, part := range strings.Split(header, ",") {
			tag := strings.TrimSpace(part)
			if tag == "" {
				continue
			}
			if tag == "*" {
				return true
			}
			tag = strings.TrimPrefix(tag, "W/")
			tag = strings.TrimPrefix(tag, "w/")
			tag = strings.Trim(tag, `"`)
			if tag == etag {
				return true
			}
		}
	}
	return false
}

var pngFileSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

func validateStatusBackgroundImage(raw []byte) (mime string, width, height int, err error) {
	if len(raw) == 0 {
		return "", 0, 0, errors.New("请上传背景图片内容")
	}

	switch {
	case len(raw) >= 3 && raw[0] == 0xFF && raw[1] == 0xD8 && raw[2] == 0xFF:
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(raw))
		if err != nil {
			return "", 0, 0, errors.New("JPEG 图片无效或已损坏")
		}
		if err := validateImageBounds(cfg.Width, cfg.Height); err != nil {
			return "", 0, 0, err
		}
		if _, err := jpeg.Decode(bytes.NewReader(raw)); err != nil {
			return "", 0, 0, errors.New("JPEG 图片解码失败或数据不完整")
		}
		return "image/jpeg", cfg.Width, cfg.Height, nil

	case bytes.HasPrefix(raw, pngFileSignature):
		cfg, err := png.DecodeConfig(bytes.NewReader(raw))
		if err != nil {
			return "", 0, 0, errors.New("PNG 图片无效或已损坏")
		}
		if err := validateImageBounds(cfg.Width, cfg.Height); err != nil {
			return "", 0, 0, err
		}
		if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
			return "", 0, 0, errors.New("PNG 图片解码失败或数据不完整")
		}
		return "image/png", cfg.Width, cfg.Height, nil

	case len(raw) >= 20 && string(raw[:4]) == "RIFF" && string(raw[8:12]) == "WEBP":
		wPx, hPx, err := validateWebP(raw)
		if err != nil {
			return "", 0, 0, err
		}
		return "image/webp", wPx, hPx, nil

	default:
		return "", 0, 0, errors.New("仅支持 JPEG、PNG 或 WebP 格式的图片")
	}
}

func validateImageBounds(width, height int) error {
	if width <= 0 || height <= 0 {
		return errors.New("图片尺寸无效")
	}
	if width > maxStatusBackgroundDimension || height > maxStatusBackgroundDimension {
		return fmt.Errorf("图片宽高均不能超过 %d 像素", maxStatusBackgroundDimension)
	}
	return nil
}

func validateWebP(raw []byte) (int, int, error) {
	if len(raw) < 20 || string(raw[:4]) != "RIFF" || string(raw[8:12]) != "WEBP" {
		return 0, 0, errors.New("WebP 图片头部无效")
	}
	riffSize := int64(binary.LittleEndian.Uint32(raw[4:8]))
	if riffSize < 12 || riffSize+8 != int64(len(raw)) {
		return 0, 0, errors.New("WebP 文件长度与容器头不匹配")
	}

	pos := 12
	firstChunk := true
	seenVP8X := false
	hasFrame := false
	width, height := 0, 0

	for pos < len(raw) {
		if pos+8 > len(raw) {
			return 0, 0, errors.New("WebP 数据块头不完整")
		}
		fourCC := string(raw[pos : pos+4])
		chunkLenU := binary.LittleEndian.Uint32(raw[pos+4 : pos+8])
		if int64(chunkLenU) > int64(len(raw)-(pos+8)) {
			return 0, 0, errors.New("WebP 数据块长度越界")
		}
		chunkLen := int(chunkLenU)
		payloadStart := pos + 8
		payloadEnd := payloadStart + chunkLen
		paddedEnd := payloadEnd + (chunkLen & 1)
		if paddedEnd > len(raw) {
			return 0, 0, errors.New("WebP 数据块缺少对齐字节")
		}
		payload := raw[payloadStart:payloadEnd]

		if firstChunk {
			firstChunk = false
			switch fourCC {
			case "VP8 ":
				wPx, hPx, err := parseWebPVP8Header(payload)
				if err != nil {
					return 0, 0, err
				}
				width, height = wPx, hPx
				hasFrame = true
			case "VP8L":
				wPx, hPx, err := parseWebPVP8LHeader(payload)
				if err != nil {
					return 0, 0, err
				}
				width, height = wPx, hPx
				hasFrame = true
			case "VP8X":
				wPx, hPx, err := parseWebPVP8XHeader(payload)
				if err != nil {
					return 0, 0, err
				}
				width, height = wPx, hPx
				seenVP8X = true
			default:
				return 0, 0, errors.New("WebP 缺少有效的图像头块")
			}
		} else if seenVP8X {
			switch fourCC {
			case "VP8 ":
				wPx, hPx, err := parseWebPVP8Header(payload)
				if err != nil {
					return 0, 0, err
				}
				if wPx > width || hPx > height {
					return 0, 0, errors.New("WebP 帧尺寸超出画布")
				}
				hasFrame = true
			case "VP8L":
				wPx, hPx, err := parseWebPVP8LHeader(payload)
				if err != nil {
					return 0, 0, err
				}
				if wPx > width || hPx > height {
					return 0, 0, errors.New("WebP 帧尺寸超出画布")
				}
				hasFrame = true
			case "ANMF":
				ok, err := validateWebPANMF(payload, width, height)
				if err != nil {
					return 0, 0, err
				}
				if ok {
					hasFrame = true
				}
			}
		}

		pos = paddedEnd
	}

	if !hasFrame {
		return 0, 0, errors.New("WebP 缺少图像帧数据")
	}
	if err := validateImageBounds(width, height); err != nil {
		return 0, 0, err
	}
	return width, height, nil
}

func parseWebPVP8Header(payload []byte) (int, int, error) {
	if len(payload) < 10 {
		return 0, 0, errors.New("WebP VP8 帧头不完整")
	}
	frameTag := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16
	if frameTag&1 != 0 {
		return 0, 0, errors.New("WebP VP8 首帧必须为关键帧")
	}
	firstPartitionSize := int(frameTag >> 5)
	if 10+firstPartitionSize > len(payload) {
		return 0, 0, errors.New("WebP VP8 数据长度不足")
	}
	if payload[3] != 0x9d || payload[4] != 0x01 || payload[5] != 0x2a {
		return 0, 0, errors.New("WebP VP8 起始码无效")
	}
	wPx := int(binary.LittleEndian.Uint16(payload[6:8]) & 0x3fff)
	hPx := int(binary.LittleEndian.Uint16(payload[8:10]) & 0x3fff)
	if wPx <= 0 || hPx <= 0 {
		return 0, 0, errors.New("WebP VP8 尺寸无效")
	}
	return wPx, hPx, nil
}

func parseWebPVP8LHeader(payload []byte) (int, int, error) {
	if len(payload) < 5 {
		return 0, 0, errors.New("WebP VP8L 帧头不完整")
	}
	if payload[0] != 0x2f {
		return 0, 0, errors.New("WebP VP8L 签名无效")
	}
	bits := binary.LittleEndian.Uint32(payload[1:5])
	if (bits>>29)&0x7 != 0 {
		return 0, 0, errors.New("WebP VP8L 版本号无效")
	}
	wPx := int(bits&0x3fff) + 1
	hPx := int((bits>>14)&0x3fff) + 1
	if wPx <= 0 || hPx <= 0 {
		return 0, 0, errors.New("WebP VP8L 尺寸无效")
	}
	return wPx, hPx, nil
}

func parseWebPVP8XHeader(payload []byte) (int, int, error) {
	if len(payload) != 10 {
		return 0, 0, errors.New("WebP VP8X 块长度无效")
	}
	if payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
		return 0, 0, errors.New("WebP VP8X 保留字段无效")
	}
	wPx := int(uint32(payload[4])|uint32(payload[5])<<8|uint32(payload[6])<<16) + 1
	hPx := int(uint32(payload[7])|uint32(payload[8])<<8|uint32(payload[9])<<16) + 1
	if err := validateImageBounds(wPx, hPx); err != nil {
		return 0, 0, err
	}
	return wPx, hPx, nil
}

func validateWebPANMF(payload []byte, canvasW, canvasH int) (bool, error) {
	if len(payload) < 16 {
		return false, errors.New("WebP ANMF 帧数据不完整")
	}
	frameW := int(uint32(payload[6])|uint32(payload[7])<<8|uint32(payload[8])<<16) + 1
	frameH := int(uint32(payload[9])|uint32(payload[10])<<8|uint32(payload[11])<<16) + 1
	if frameW > canvasW || frameH > canvasH {
		return false, errors.New("WebP 动画帧超出画布尺寸")
	}
	pos := 16
	hasSubFrame := false
	for pos < len(payload) {
		if pos+8 > len(payload) {
			return false, errors.New("WebP ANMF 子块头不完整")
		}
		fourCC := string(payload[pos : pos+4])
		subLenU := binary.LittleEndian.Uint32(payload[pos+4 : pos+8])
		if int64(subLenU) > int64(len(payload)-(pos+8)) {
			return false, errors.New("WebP ANMF 子块长度越界")
		}
		subLen := int(subLenU)
		subStart := pos + 8
		subEnd := subStart + subLen
		subPadded := subEnd + (subLen & 1)
		if subPadded > len(payload) {
			return false, errors.New("WebP ANMF 子块对齐无效")
		}
		subPayload := payload[subStart:subEnd]
		switch fourCC {
		case "VP8 ":
			if _, _, err := parseWebPVP8Header(subPayload); err != nil {
				return false, err
			}
			hasSubFrame = true
		case "VP8L":
			if _, _, err := parseWebPVP8LHeader(subPayload); err != nil {
				return false, err
			}
			hasSubFrame = true
		}
		pos = subPadded
	}
	return hasSubFrame, nil
}
