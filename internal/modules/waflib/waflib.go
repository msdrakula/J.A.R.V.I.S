package waflib

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

// Signature описывает пассивную сигнатуру WAF/CDN по заголовкам, cookie или телу ответа.
type Signature struct {
	Name      string   `yaml:"name"`
	Headers   []string `yaml:"headers"`
	Cookies   []string `yaml:"cookies"`
	BodyWords []string `yaml:"body_words"`
}

// Detection — результат идентификации защитного механизма.
type Detection struct {
	Name     string
	Evidence []string
}

// Detector выполняет пассивную идентификацию WAF/CDN по уже полученным ответам.
type Detector struct {
	client     *httpclient.Client
	store      *storage.Store
	signatures []Signature
}

// LoadSignatures читает YAML-файл сигнатур.
func LoadSignatures(path string) ([]Signature, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sigs []Signature
	if err := yaml.Unmarshal(data, &sigs); err != nil {
		return nil, err
	}
	return sigs, nil
}

// New создаёт детектор с загруженными сигнатурами.
func New(client *httpclient.Client, store *storage.Store, signatures []Signature) *Detector {
	return &Detector{client: client, store: store, signatures: signatures}
}

// Detect делает один обычный GET-запрос и пассивно анализирует ответ.
// Найденные совпадения сохраняются в findings с severity "info".
func (d *Detector) Detect(scanID, rawURL string) ([]Detection, error) {
	if d == nil || d.client == nil {
		return nil, fmt.Errorf("waf detector is not initialized")
	}
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("url is required")
	}
	resp, err := d.client.Do(httpclient.RequestOptions{Method: "GET", URL: rawURL, FollowRedirects: true})
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", rawURL, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from %s", rawURL)
	}

	detections := MatchSignatures(d.signatures, resp.Headers, resp.Body)

	for _, det := range detections {
		if d.store != nil {
			_ = d.store.AddFinding(scanID, storage.Finding{
				Host:        rawURL,
				URL:         rawURL,
				Severity:    "info",
				Category:    "waf-detection",
				Name:        "WAF/CDN detected: " + det.Name,
				Description: "Protective mechanism identified: " + det.Name,
				Evidence:    strings.Join(det.Evidence, "; "),
			})
		}
	}

	return detections, nil
}

// MatchSignatures сопоставляет заголовки и тело ответа со списком сигнатур.
// Вынесено отдельно для удобства юнит-тестирования.
func MatchSignatures(signatures []Signature, headers http.Header, body []byte) []Detection {
	var detections []Detection
	bodyLower := strings.ToLower(string(body))

	for _, sig := range signatures {
		var evidence []string

		for _, headerName := range sig.Headers {
			if headers.Get(headerName) != "" {
				evidence = append(evidence, headerName+" header present")
			}
		}

		for _, cookieName := range sig.Cookies {
			for _, cookieHeader := range headers.Values("Set-Cookie") {
				if strings.Contains(strings.ToLower(cookieHeader), strings.ToLower(cookieName)) {
					evidence = append(evidence, cookieName+" cookie present")
				}
			}
		}

		for _, word := range sig.BodyWords {
			if strings.Contains(bodyLower, strings.ToLower(word)) {
				evidence = append(evidence, "body contains signature word")
			}
		}

		if len(evidence) > 0 {
			detections = append(detections, Detection{Name: sig.Name, Evidence: evidence})
		}
	}

	return detections
}
