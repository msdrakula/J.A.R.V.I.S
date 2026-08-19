package resilience

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/msdrakula/J.A.R.V.I.S/internal/httpclient"
	"github.com/msdrakula/J.A.R.V.I.S/internal/storage"
)

// markerToken — уникальный алфавитно-цифровой маркер для проверки отражения ввода.
// Не является пейлоадом: не содержит синтаксиса каких-либо языков.
const markerToken = "JARVISMARK7F3A9"

// markerTag — инертная строка, похожая на HTML-тег. Используется только для
// проверки того, кодирует ли приложение вывод. Не содержит скриптов и обработчиков.
const markerTag = "<jarvismark>"

// markerQuote — одиночная кавычка для проверки обработки синтаксических
// символов. Детектируется только факт 5xx-ответа (обработка ошибок),
// без каких-либо попыток построения выражений.
const markerQuote = "'"

// Checker выполняет безопасную проверку устойчивости обработки ввода:
// только маркерные строки, только факт отражения или 5xx-статуса.
type Checker struct {
	client *httpclient.Client
	store  *storage.Store
}

func New(client *httpclient.Client, store *storage.Store) *Checker {
	return &Checker{client: client, store: store}
}

// Check читает параметры, найденные recon-этапом, и для каждого отправляет
// не более двух безобидных запросов с маркерными значениями.
func (c *Checker) Check(scanID string) error {
	if c.client == nil || c.store == nil {
		return fmt.Errorf("resilience checker requires client and store")
	}

	params, err := c.store.GetParameters(scanID)
	if err != nil {
		return fmt.Errorf("load parameters: %w", err)
	}

	for _, param := range params {
		if param.URL == "" || param.Name == "" {
			continue
		}
		if err := c.checkParam(scanID, param); err != nil {
			// Ошибка одного параметра не должна останавливать весь аудит.
			continue
		}
	}
	return nil
}

func (c *Checker) checkParam(scanID string, param storage.Parameter) error {
	// Шаг 1: tag-маркер — проверка кодирования вывода.
	tagURL, err := buildURL(param.URL, param.Name, markerTag)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(httpclient.RequestOptions{Method: "GET", URL: tagURL, FollowRedirects: true})
	if err != nil {
		return err
	}

	if resp.StatusCode >= 500 {
		_ = c.store.AddFinding(scanID, storage.Finding{
			Host:        hostOf(param.URL),
			URL:         param.URL,
			Severity:    "medium",
			Category:    "input-resilience",
			Name:        "Improper error handling on unexpected input",
			Description: fmt.Sprintf("Parameter %q caused a %d response to unexpected input; verify server-side validation and error handling", param.Name, resp.StatusCode),
			Evidence:    fmt.Sprintf("status=%d", resp.StatusCode),
		})
		return nil
	}

	if strings.Contains(string(resp.Body), markerTag) {
		_ = c.store.AddFinding(scanID, storage.Finding{
			Host:        hostOf(param.URL),
			URL:         param.URL,
			Severity:    "low",
			Category:    "input-resilience",
			Name:        "Input reflected without output encoding",
			Description: fmt.Sprintf("Parameter %q reflects a tag-like marker; verify output encoding for this input", param.Name),
			Evidence:    "marker reflected in response body",
		})
		return nil
	}

	// Шаг 2: одиночная кавычка — только детекция 5xx (обработка ошибок).
	quoteURL, err := buildURL(param.URL, param.Name, markerToken+markerQuote)
	if err != nil {
		return err
	}

	quoteResp, err := c.client.Do(httpclient.RequestOptions{Method: "GET", URL: quoteURL, FollowRedirects: true})
	if err != nil {
		return err
	}

	if quoteResp.StatusCode >= 500 {
		_ = c.store.AddFinding(scanID, storage.Finding{
			Host:        hostOf(param.URL),
			URL:         param.URL,
			Severity:    "medium",
			Category:    "input-resilience",
			Name:        "Improper error handling on syntax character",
			Description: fmt.Sprintf("Parameter %q returned %d on a quote character; verify input validation and error handling", param.Name, quoteResp.StatusCode),
			Evidence:    fmt.Sprintf("status=%d", quoteResp.StatusCode),
		})
	}
	return nil
}

// buildURL подставляет маркерное значение в query-параметр, сохраняя остальные.
func buildURL(rawURL, name, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}
