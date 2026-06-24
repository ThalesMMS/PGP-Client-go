package pgp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

const maxKeyserverResponse = 16 << 20

type KeyserverClient struct {
	baseURL *url.URL
	client  *http.Client
}

func NewKeyserverClient(rawURL string) (*KeyserverClient, error) {
	if strings.TrimSpace(rawURL) == "" {
		rawURL = "https://keys.openpgp.org"
	}
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL do servidor de chaves: %w", err)
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1")) {
		return nil, errors.New("o servidor de chaves deve usar HTTPS")
	}
	if base.Host == "" {
		return nil, errors.New("servidor de chaves inválido")
	}
	base.Path = strings.TrimSuffix(base.Path, "/")
	return &KeyserverClient{
		baseURL: base,
		client: &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("excesso de redirecionamentos")
				}
				if req.URL.Scheme != "https" && !(req.URL.Scheme == "http" && (req.URL.Hostname() == "localhost" || req.URL.Hostname() == "127.0.0.1")) {
					return errors.New("redirecionamento inseguro bloqueado")
				}
				return nil
			},
		},
	}, nil
}

func (c *KeyserverClient) endpoint(path string) *url.URL {
	copyURL := *c.baseURL
	copyURL.Path = copyURL.Path + path
	return &copyURL
}

func (c *KeyserverClient) Search(ctx context.Context, query string) ([]model.KeyserverResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("consulta vazia")
	}
	endpoint := c.endpoint("/pks/lookup")
	params := endpoint.Query()
	params.Set("op", "index")
	params.Set("options", "mr")
	params.Set("search", query)
	endpoint.RawQuery = params.Encode()
	body, err := c.do(ctx, http.MethodGet, endpoint.String(), nil, "")
	if err != nil {
		return nil, err
	}
	return parseMachineReadableIndex(body)
}

func (c *KeyserverClient) Fetch(ctx context.Context, fingerprintOrKeyID string) ([]byte, error) {
	search := strings.TrimSpace(fingerprintOrKeyID)
	if search == "" {
		return nil, errors.New("fingerprint ou Key ID vazio")
	}
	if !strings.Contains(search, "@") && !strings.HasPrefix(strings.ToLower(search), "0x") {
		search = "0x" + strings.ReplaceAll(search, " ", "")
	}
	endpoint := c.endpoint("/pks/lookup")
	params := endpoint.Query()
	params.Set("op", "get")
	params.Set("options", "mr")
	params.Set("search", search)
	endpoint.RawQuery = params.Encode()
	return c.do(ctx, http.MethodGet, endpoint.String(), nil, "")
}

func (c *KeyserverClient) Upload(ctx context.Context, armoredPublicKey []byte) error {
	form := url.Values{}
	form.Set("keytext", string(armoredPublicKey))
	endpoint := c.endpoint("/pks/add")
	_, err := c.do(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	return err
}

func (c *KeyserverClient) do(ctx context.Context, method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "PGP-Client-Go/1.0")
	req.Header.Set("Accept", "application/pgp-keys, text/plain;q=0.9, */*;q=0.1")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("servidor de chaves: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxKeyserverResponse+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyserverResponse {
		return nil, errors.New("resposta do servidor de chaves excede 16 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(data))
		if len(message) > 500 {
			message = message[:500]
		}
		return nil, fmt.Errorf("servidor de chaves respondeu %s: %s", resp.Status, message)
	}
	return data, nil
}

func (s *Service) SearchKeyserver(ctx context.Context, query string) ([]model.KeyserverResult, error) {
	client, err := NewKeyserverClient(s.Settings().DefaultKeyserver)
	if err != nil {
		return nil, err
	}
	return client.Search(ctx, query)
}

func (s *Service) ImportFromKeyserver(ctx context.Context, fingerprintOrKeyID string) ([]model.KeyInfo, error) {
	client, err := NewKeyserverClient(s.Settings().DefaultKeyserver)
	if err != nil {
		return nil, err
	}
	data, err := client.Fetch(ctx, fingerprintOrKeyID)
	if err != nil {
		return nil, err
	}
	infos, err := s.Import(data)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, info := range infos {
		_ = s.store.UpdateMetadata(info.Fingerprint, func(metadata *model.KeyMetadata) {
			metadata.LastKeyserverSync = &now
		})
	}
	return infos, nil
}

func (s *Service) UploadToKeyserver(ctx context.Context, fingerprint string) error {
	client, err := NewKeyserverClient(s.Settings().DefaultKeyserver)
	if err != nil {
		return err
	}
	publicKey, err := s.ExportPublic(fingerprint)
	if err != nil {
		return err
	}
	if err := client.Upload(ctx, publicKey); err != nil {
		return err
	}
	now := time.Now().UTC()
	return s.store.UpdateMetadata(fingerprint, func(metadata *model.KeyMetadata) {
		metadata.LastKeyserverSync = &now
	})
}

func parseMachineReadableIndex(data []byte) ([]model.KeyserverResult, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var results []model.KeyserverResult
	var current *model.KeyserverResult
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		switch parts[0] {
		case "pub":
			if len(parts) < 7 {
				continue
			}
			result := model.KeyserverResult{
				KeyID:     strings.ToUpper(parts[1]),
				Algorithm: hkpAlgorithm(parts[2]),
				Bits:      atoi(parts[3]),
				CreatedAt: unixTime(parts[4]),
			}
			if expires := unixTime(parts[5]); !expires.IsZero() {
				result.ExpiresAt = &expires
			}
			flags := parts[6]
			result.Revoked = strings.Contains(flags, "r")
			result.Disabled = strings.Contains(flags, "d")
			result.Expired = strings.Contains(flags, "e")
			if len(parts) > 7 {
				result.Fingerprint = strings.ToUpper(parts[7])
			}
			results = append(results, result)
			current = &results[len(results)-1]
		case "uid":
			if current == nil || len(parts) < 2 {
				continue
			}
			uid, err := url.QueryUnescape(parts[1])
			if err == nil {
				current.UserIDs = append(current.UserIDs, uid)
			}
		case "fpr":
			if current != nil && len(parts) > 1 {
				current.Fingerprint = strings.ToUpper(parts[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func atoi(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func unixTime(value string) time.Time {
	unix, _ := strconv.ParseInt(value, 10, 64)
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

func hkpAlgorithm(value string) string {
	switch value {
	case "1", "2", "3":
		return "RSA"
	case "16", "20":
		return "ElGamal"
	case "17":
		return "DSA"
	case "18":
		return "ECDH"
	case "19":
		return "ECDSA"
	case "22":
		return "EdDSA"
	default:
		return "OpenPGP (" + value + ")"
	}
}
