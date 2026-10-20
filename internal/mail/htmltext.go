package mail

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// htmlToText renders HTML as plain text and drops content a human reader
// would not see: non-content elements (script, style, head, media, forms),
// elements with the hidden attribute, inline styles that hide content
// (display:none, visibility:hidden, opacity≈0, font-size≈0, zero-size boxes
// with overflow:hidden, off-screen positioning, clip, mso-hide:all,
// transparent text) and elements whose class or id is hidden by a simple
// top-level <style> rule. Detection is best-effort; callers must still treat
// the output as untrusted.
//
// The result is capped at roughly limit bytes; truncated reports whether
// input was dropped.
func htmlToText(src string, limit int) (text string, hidden int, truncated bool) {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		// html.Parse only fails on reader errors; fall back to nothing
		// rather than leaking raw markup.
		return "", 0, false
	}
	hr := hiddenRules{classes: map[string]bool{}, ids: map[string]bool{}}
	collectStyleRules(doc, &hr)
	c := &htmlConv{rules: &hr, limit: limit}
	c.walk(doc)
	return tidyLines(cleanText(c.b.String())), c.hidden, c.truncated
}

type hiddenRules struct {
	classes map[string]bool
	ids     map[string]bool
}

type htmlConv struct {
	b         strings.Builder
	rules     *hiddenRules
	limit     int
	truncated bool
	hidden    int
	pre       int
	lists     []int // per open list: -1 for <ul>, next number for <ol>
	nl        int   // trailing newlines in b
	space     bool  // a collapsible space is pending
}

// skipElements never contribute visible text in a mail reader.
var skipElements = map[atom.Atom]bool{
	atom.Head: true, atom.Title: true, atom.Script: true, atom.Style: true,
	atom.Meta: true, atom.Link: true, atom.Noscript: true, atom.Template: true,
	atom.Iframe: true, atom.Frame: true, atom.Frameset: true, atom.Object: true,
	atom.Embed: true, atom.Param: true, atom.Svg: true, atom.Math: true,
	atom.Canvas: true, atom.Audio: true, atom.Video: true, atom.Source: true,
	atom.Track: true, atom.Img: true, atom.Picture: true, atom.Map: true,
	atom.Area: true, atom.Input: true, atom.Select: true, atom.Option: true,
	atom.Textarea: true, atom.Datalist: true,
}

var blockElements = map[atom.Atom]bool{
	atom.Address: true, atom.Article: true, atom.Aside: true, atom.Center: true,
	atom.Dd: true, atom.Details: true, atom.Dialog: true, atom.Div: true,
	atom.Dl: true, atom.Dt: true, atom.Fieldset: true, atom.Figcaption: true,
	atom.Figure: true, atom.Footer: true, atom.Form: true, atom.Header: true,
	atom.Main: true, atom.Nav: true, atom.Section: true, atom.Summary: true,
	atom.Tbody: true, atom.Thead: true, atom.Tfoot: true,
	atom.Caption: true, atom.Ul: true, atom.Ol: true,
}

var paragraphElements = map[atom.Atom]bool{
	atom.P: true, atom.Table: true, atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true,
	atom.H5: true, atom.H6: true, atom.Pre: true, atom.Blockquote: true,
}

func (c *htmlConv) full() bool {
	if c.b.Len() >= c.limit {
		c.truncated = true
		return true
	}
	return false
}

func (c *htmlConv) walk(n *html.Node) {
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if c.full() {
			return
		}
		c.node(child)
	}
}

func (c *htmlConv) node(n *html.Node) {
	switch n.Type {
	case html.TextNode:
		c.text(n.Data)
		return
	case html.ElementNode:
	case html.DocumentNode:
		c.walk(n)
		return
	default: // comments, doctype
		return
	}
	if skipElements[n.DataAtom] {
		return
	}
	if c.isHidden(n) {
		c.hidden++
		return
	}
	switch n.DataAtom {
	case atom.Br:
		c.newline(1)
	case atom.Hr:
		c.newline(1)
		c.raw("---")
		c.newline(1)
	case atom.Li:
		c.newline(1)
		c.listMarker()
		c.walk(n)
		c.newline(1)
	case atom.Ul, atom.Ol:
		start := -1
		if n.DataAtom == atom.Ol {
			start = 1
			if v, err := strconv.Atoi(attr(n, "start")); err == nil {
				start = v
			}
		}
		gap := 2 // top-level lists are separated like paragraphs
		if len(c.lists) > 0 {
			gap = 1
		}
		c.lists = append(c.lists, start)
		c.newline(gap)
		c.walk(n)
		c.newline(gap)
		c.lists = c.lists[:len(c.lists)-1]
	case atom.Tr:
		c.newline(1)
		c.walk(n)
		c.newline(1)
	case atom.Td, atom.Th:
		if c.nl == 0 && c.b.Len() > 0 {
			c.raw("\t")
		}
		c.walk(n)
	case atom.A:
		c.link(n)
	case atom.Blockquote:
		c.blockquote(n)
	case atom.Pre:
		c.newline(2)
		c.pre++
		c.walk(n)
		c.pre--
		c.newline(2)
	default:
		switch {
		case paragraphElements[n.DataAtom]:
			c.newline(2)
			c.walk(n)
			c.newline(2)
		case blockElements[n.DataAtom]:
			c.newline(1)
			c.walk(n)
			c.newline(1)
		default:
			c.walk(n)
		}
	}
}

func (c *htmlConv) listMarker() {
	depth := len(c.lists)
	if depth == 0 {
		c.raw("- ")
		return
	}
	c.raw(strings.Repeat("  ", depth-1))
	if n := c.lists[depth-1]; n >= 0 {
		c.raw(strconv.Itoa(n) + ". ")
		c.lists[depth-1]++
	} else {
		c.raw("- ")
	}
}

// link renders the anchor text and, for web/mail links whose target differs
// from the text, the target in angle brackets.
func (c *htmlConv) link(n *html.Node) {
	start := c.b.Len()
	c.walk(n)
	href := strings.TrimSpace(attr(n, "href"))
	lower := strings.ToLower(href)
	if !(strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "mailto:")) {
		return
	}
	text := strings.TrimSpace(c.b.String()[start:])
	if text == href || "mailto:"+text == href || strings.TrimSuffix(href, "/") == strings.TrimSuffix(text, "/") {
		return
	}
	href = cleanHeader(href, 500)
	if text == "" {
		c.text(href)
		return
	}
	c.text(" <" + href + ">")
}

func (c *htmlConv) blockquote(n *html.Node) {
	sub := &htmlConv{rules: c.rules, limit: max(c.limit-c.b.Len(), 0)}
	sub.walk(n)
	c.hidden += sub.hidden
	c.truncated = c.truncated || sub.truncated
	inner := tidyLines(sub.b.String())
	if inner == "" {
		return
	}
	c.newline(2)
	for i, line := range strings.Split(inner, "\n") {
		if i > 0 {
			c.newline(1)
		}
		c.raw("> " + line)
	}
	c.newline(2)
}

// text appends a text node, collapsing whitespace outside <pre>.
func (c *htmlConv) text(s string) {
	if c.pre > 0 {
		c.raw(s)
		return
	}
	for i, w := range strings.Fields(s) {
		if (i > 0 || c.space || startsWithSpace(s)) && c.nl == 0 && c.b.Len() > 0 {
			c.b.WriteByte(' ')
		}
		c.space = false
		c.b.WriteString(w)
		c.nl = 0
	}
	if endsWithSpace(s) {
		c.space = true
	}
}

func (c *htmlConv) raw(s string) {
	if s == "" {
		return
	}
	c.b.WriteString(s)
	c.space = false
	if strings.HasSuffix(s, "\n") {
		c.nl = len(s) - len(strings.TrimRight(s, "\n"))
	} else {
		c.nl = 0
	}
}

// newline ensures at least n trailing newlines (never at the very start).
func (c *htmlConv) newline(n int) {
	c.space = false
	if c.b.Len() == 0 {
		return
	}
	for c.nl < n {
		c.b.WriteByte('\n')
		c.nl++
	}
}

func startsWithSpace(s string) bool { return s != "" && isHTMLSpace(s[0]) }
func endsWithSpace(s string) bool   { return s != "" && isHTMLSpace(s[len(s)-1]) }
func isHTMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Namespace == "" && strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}

func (c *htmlConv) isHidden(n *html.Node) bool {
	if hasAttr(n, "hidden") {
		return true
	}
	if s := attr(n, "style"); s != "" && styleHides(parseDecls(s)) {
		return true
	}
	if id := strings.TrimSpace(attr(n, "id")); id != "" && c.rules.ids[id] {
		return true
	}
	for cls := range strings.FieldsSeq(attr(n, "class")) {
		if c.rules.classes[cls] {
			return true
		}
	}
	return false
}

// parseDecls parses a CSS declaration list into lower-cased property/value
// pairs with !important removed. Later declarations win.
func parseDecls(s string) map[string]string {
	decls := map[string]string{}
	for d := range strings.SplitSeq(s, ";") {
		k, v, ok := strings.Cut(d, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))
		v = strings.TrimSpace(strings.TrimSuffix(v, "!important"))
		if k != "" {
			decls[k] = v
		}
	}
	return decls
}

var lengthRE = regexp.MustCompile(`^([+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+))([a-z%]*)$`)

// cssPx converts a CSS length to approximate CSS pixels (16px font base).
func cssPx(v string) (float64, bool) {
	m := lengthRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	switch m[2] {
	case "", "px":
		if m[2] == "" && f != 0 {
			return 0, false
		}
		return f, true
	case "pt":
		return f * 4 / 3, true
	case "em", "rem":
		return f * 16, true
	case "%":
		return f * 0.16, true
	case "pc":
		return f * 16, true
	case "mm":
		return f * 3.78, true
	case "cm":
		return f * 37.8, true
	case "in":
		return f * 96, true
	}
	return 0, false
}

func pxAtMost(v string, limit float64) bool {
	px, ok := cssPx(v)
	return ok && px <= limit
}

var (
	clipZeroRE  = regexp.MustCompile(`^rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)$`)
	clipInsetRE = regexp.MustCompile(`^inset\(\s*(50|100)%\s*\)$`)
	scaleZeroRE = regexp.MustCompile(`scale[xy]?\(\s*0(\.0+)?\s*(,\s*0(\.0+)?\s*)?\)`)
	transpRE    = regexp.MustCompile(`^(transparent|rgba\(.*,\s*0(\.0+)?\s*\)|hsla\(.*,\s*0(\.0+)?\s*\))$`)
)

// styleHides reports whether a declaration block hides its element.
func styleHides(d map[string]string) bool {
	if d["display"] == "none" || d["mso-hide"] == "all" {
		return true
	}
	if v := d["visibility"]; v == "hidden" || v == "collapse" {
		return true
	}
	if v, ok := d["opacity"]; ok {
		if f, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64); err == nil {
			if strings.HasSuffix(v, "%") {
				f /= 100
			}
			if f < 0.1 {
				return true
			}
		}
	}
	if v, ok := d["font-size"]; ok && pxAtMost(v, 2) {
		return true
	}
	if transpRE.MatchString(d["color"]) {
		return true
	}
	clipped := d["overflow"] == "hidden" || d["overflow-x"] == "hidden" || d["overflow-y"] == "hidden"
	if clipped {
		for _, k := range []string{"height", "max-height", "width", "max-width"} {
			if v, ok := d[k]; ok && pxAtMost(v, 1) {
				return true
			}
		}
	}
	if clipZeroRE.MatchString(d["clip"]) || clipInsetRE.MatchString(d["clip-path"]) {
		return true
	}
	if scaleZeroRE.MatchString(d["transform"]) {
		return true
	}
	if v, ok := d["text-indent"]; ok && pxAtMost(v, -500) {
		return true
	}
	if p := d["position"]; p == "absolute" || p == "fixed" {
		for _, k := range []string{"left", "top", "right", "bottom"} {
			if v, ok := d[k]; ok && pxAtMost(v, -500) {
				return true
			}
		}
	}
	return false
}

var (
	cssCommentRE   = regexp.MustCompile(`(?s)/\*.*?\*/`)
	simpleClassRE  = regexp.MustCompile(`^(?:[a-z][a-z0-9]*)?\.([A-Za-z_][\w-]*)$`)
	simpleIDRE     = regexp.MustCompile(`^(?:[a-z][a-z0-9]*)?#([A-Za-z_][\w-]*)$`)
	maxStyleSource = 256 << 10
)

// collectStyleRules finds top-level rules in <style> elements whose
// declarations hide content and records their simple class/id selectors.
// Rules inside at-rules (@media, @supports, ...) are conditional and ignored.
func collectStyleRules(n *html.Node, hr *hiddenRules) {
	if n.Type == html.ElementNode && n.DataAtom == atom.Style {
		var css strings.Builder
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			if ch.Type == html.TextNode && css.Len() < maxStyleSource {
				css.WriteString(ch.Data)
			}
		}
		parseHiddenCSS(css.String(), hr)
		return
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		collectStyleRules(ch, hr)
	}
}

func parseHiddenCSS(css string, hr *hiddenRules) {
	css = cssCommentRE.ReplaceAllString(css, " ")
	depth, atDepth := 0, -1
	selStart, blockStart := 0, 0
	for i := 0; i < len(css); i++ {
		switch css[i] {
		case '@':
			if depth == 0 && atDepth < 0 {
				atDepth = 0
			}
		case ';':
			if depth == 0 && atDepth == 0 {
				atDepth = -1 // statement at-rule like @import
				selStart = i + 1
			}
		case '{':
			if depth == 0 {
				blockStart = i + 1
			}
			depth++
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth != 0 {
				continue
			}
			if atDepth < 0 && styleHides(parseDecls(css[blockStart:i])) {
				for sel := range strings.SplitSeq(css[selStart:blockStart-1], ",") {
					sel = strings.TrimSpace(sel)
					if m := simpleClassRE.FindStringSubmatch(sel); m != nil {
						hr.classes[m[1]] = true
					} else if m := simpleIDRE.FindStringSubmatch(sel); m != nil {
						hr.ids[m[1]] = true
					}
				}
			}
			atDepth = -1
			selStart = i + 1
		}
	}
}
