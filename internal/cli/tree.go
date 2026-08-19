package cli

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

func colorizeStatus(status int, text string) string {
	if os.Getenv("NO_COLOR") != "" {
		return text
	}
	switch {
	case status >= 200 && status < 300:
		return ansiGreen + text + ansiReset
	case status >= 300 && status < 400:
		return ansiYellow + text + ansiReset
	case status >= 400:
		return ansiRed + text + ansiReset
	default:
		return text
	}
}

type pathNode struct {
	name     string
	status   int
	children map[string]*pathNode
}

func newPathNode(name string) *pathNode {
	return &pathNode{name: name, children: map[string]*pathNode{}}
}

func renderPathTree(rows []map[string]interface{}) string {
	root := newPathNode("")

	for _, row := range rows {
		rawURL := fmt.Sprintf("%v", row["url"])
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		status := parseIntValue(row["status_code"])

		path := u.Path
		if path == "" {
			path = "/"
		}
		segments := strings.Split(strings.Trim(path, "/"), "/")
		if path == "/" {
			segments = []string{""}
		}

		current := root
		for _, segment := range segments {
			child, ok := current.children[segment]
			if !ok {
				child = newPathNode(segment)
				current.children[segment] = child
			}
			current = child
		}
		current.status = status
	}

	var b strings.Builder
	renderChildren(&b, root, "")
	return b.String()
}

func renderChildren(b *strings.Builder, node *pathNode, prefix string) {
	names := sortedChildNames(node)
	for i, name := range names {
		child := node.children[name]
		last := i == len(names)-1

		branch := "├─ "
		nextPrefix := prefix + "│  "
		if last {
			branch = "└─ "
			nextPrefix = prefix + "   "
		}

		b.WriteString(prefix + branch)
		renderChild(b, child, nextPrefix)
	}
}

func renderChild(b *strings.Builder, node *pathNode, prefix string) {
	label := "/" + node.name
	if node.name == "" {
		label = "/"
	}
	if node.status > 0 {
		b.WriteString(colorizeStatus(node.status, fmt.Sprintf("[%d] %s", node.status, label)))
	} else {
		b.WriteString(label)
	}
	b.WriteString("\n")

	names := sortedChildNames(node)
	for i, name := range names {
		child := node.children[name]
		last := i == len(names)-1

		branch := "├─ "
		nextPrefix := prefix + "│  "
		if last {
			branch = "└─ "
			nextPrefix = prefix + "   "
		}

		b.WriteString(prefix + branch)
		renderChild(b, child, nextPrefix)
	}
}

func sortedChildNames(node *pathNode) []string {
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parseIntValue(v interface{}) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case int:
		return t
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return 0
	}
}
