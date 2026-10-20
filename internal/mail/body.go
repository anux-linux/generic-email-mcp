package mail

import (
	"bytes"
	"io"
	"mime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
)

const (
	maxTextParts      = 8
	minPartFetch      = 64 << 10
	maxAttachments    = 100
	maxFilenameRunes  = 255
	bodyPartSeparator = "\n\n"
)

// textPart is a body part selected for display.
type textPart struct {
	path     []int
	html     bool
	charset  string
	encoding string
	size     uint32
}

// bodyPlan says which parts to fetch as text; everything else is listed as
// attachment metadata.
type bodyPlan struct {
	texts       []textPart
	attachments []Attachment
	// droppedTexts counts text parts beyond maxTextParts (not fetched).
	droppedTexts int
}

// planBody walks a BODYSTRUCTURE. Inline text/plain and text/html parts are
// body text; for multipart/alternative exactly one branch is chosen,
// preferring text/plain over text/html (plain text cannot hide content).
func planBody(bs imap.BodyStructure) bodyPlan {
	var p bodyPlan
	if bs != nil {
		p.visit(bs, nil)
	}
	return p
}

func (p *bodyPlan) visit(bs imap.BodyStructure, path []int) {
	switch b := bs.(type) {
	case *imap.BodyStructureMultiPart:
		if strings.EqualFold(b.Subtype, "alternative") && len(b.Children) > 0 {
			i := bestAlternative(b.Children)
			p.visit(b.Children[i], childPath(path, i))
			return
		}
		for i, ch := range b.Children {
			p.visit(ch, childPath(path, i))
		}
	case *imap.BodyStructureSinglePart:
		if path == nil {
			path = []int{1} // a non-multipart message has exactly part 1
		}
		if kind := bodyTextKind(b); kind != "" {
			if len(p.texts) == maxTextParts {
				p.droppedTexts++
				return
			}
			p.texts = append(p.texts, textPart{
				path:     path,
				html:     kind == "text/html",
				charset:  b.Params["charset"],
				encoding: b.Encoding,
				size:     b.Size,
			})
			return
		}
		if len(p.attachments) < maxAttachments {
			p.attachments = append(p.attachments, attachmentOf(path, b))
		}
	}
}

func childPath(path []int, i int) []int {
	out := make([]int, len(path)+1)
	copy(out, path)
	out[len(path)] = i + 1
	return out
}

// bodyTextKind returns "text/plain" or "text/html" for displayable inline
// text parts and "" otherwise. Named text files are attachments.
func bodyTextKind(b *imap.BodyStructureSinglePart) string {
	mt := b.MediaType()
	if mt != "text/plain" && mt != "text/html" {
		return ""
	}
	if d := b.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
		return ""
	}
	if partFilename(b) != "" {
		return ""
	}
	return mt
}

// bestAlternative scores branches: 2 if it yields text/plain, 1 for
// text/html. The last best branch wins (RFC 2046 orders by fidelity).
func bestAlternative(children []imap.BodyStructure) int {
	best, bestScore := 0, -1
	for i, ch := range children {
		s := 0
		switch {
		case containsText(ch, "text/plain"):
			s = 2
		case containsText(ch, "text/html"):
			s = 1
		}
		if s >= bestScore {
			best, bestScore = i, s
		}
	}
	return best
}

func containsText(bs imap.BodyStructure, mt string) bool {
	switch b := bs.(type) {
	case *imap.BodyStructureSinglePart:
		return bodyTextKind(b) == mt
	case *imap.BodyStructureMultiPart:
		for _, ch := range b.Children {
			if containsText(ch, mt) {
				return true
			}
		}
	}
	return false
}

func attachmentOf(path []int, b *imap.BodyStructureSinglePart) Attachment {
	size := int64(b.Size)
	if strings.EqualFold(b.Encoding, "base64") {
		size = size * 3 / 4
	}
	inline := false
	if d := b.Disposition(); d != nil {
		inline = strings.EqualFold(d.Value, "inline")
	} else {
		inline = b.ID != ""
	}
	name := partFilename(b)
	if name == "" && b.MessageRFC822 != nil && b.MessageRFC822.Envelope != nil {
		name = b.MessageRFC822.Envelope.Subject
	}
	return Attachment{
		Part:        formatPart(path),
		Filename:    cleanHeader(name, maxFilenameRunes),
		ContentType: cleanHeader(b.MediaType(), 100),
		Size:        size,
		Inline:      inline,
	}
}

func formatPart(path []int) string {
	parts := make([]string, len(path))
	for i, n := range path {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// partFilename returns the decoded filename from Content-Disposition or
// Content-Type parameters, including RFC 2231 extended and continued forms
// (filename*=utf-8”..., filename*0*=...), which BODYSTRUCTURE passes raw.
func partFilename(b *imap.BodyStructureSinglePart) string {
	if d := b.Disposition(); d != nil {
		if name := paramValue(d.Params, "filename"); name != "" {
			return name
		}
	}
	return paramValue(b.Params, "name")
}

func paramValue(params map[string]string, key string) string {
	if v := params[key]; v != "" {
		return v
	}
	var rendered []string
	for k, v := range params {
		if k == key || strings.HasPrefix(k, key+"*") {
			if !isToken(k) {
				continue
			}
			if strings.HasSuffix(k, "*") {
				// Extended values are already percent-encoded tokens.
				rendered = append(rendered, k+"="+v)
			} else {
				rendered = append(rendered, k+"="+quoteParam(v))
			}
		}
	}
	if len(rendered) == 0 {
		return ""
	}
	sort.Strings(rendered)
	_, out, err := mime.ParseMediaType("x/x; " + strings.Join(rendered, "; "))
	if err != nil {
		return ""
	}
	return out[key]
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`()<>@,;:\"/[]?=`, c) >= 0 {
			return false
		}
	}
	return true
}

func quoteParam(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`
}

// decodeTextPart undoes the transfer encoding and charset of raw part bytes.
// raw may be cut short by a partial FETCH; the decoded prefix is kept.
func decodeTextPart(tp textPart, raw []byte) string {
	h := message.Header{}
	ct := "text/plain"
	if tp.html {
		ct = "text/html"
	}
	params := map[string]string{}
	if tp.charset != "" {
		params["charset"] = tp.charset
	}
	h.SetContentType(ct, params)
	if tp.encoding != "" {
		h.Set("Content-Transfer-Encoding", tp.encoding)
	}
	if strings.EqualFold(tp.encoding, "base64") {
		raw = repairBase64(raw)
	}
	e, err := message.New(h, bytes.NewReader(raw))
	knownCharset := tp.charset != "" && !message.IsUnknownCharset(err)
	var data []byte
	if e != nil {
		// A read error means a damaged or truncated encoding; keep the
		// decoded prefix.
		data, _ = io.ReadAll(e.Body)
	}
	s := string(data)
	if !knownCharset || !utf8.ValidString(s) {
		s = decodeLegacy(s)
	}
	return s
}

// repairBase64 completes the final quantum of base64 cut short by a partial
// FETCH so the decodable prefix is not lost.
func repairBase64(raw []byte) []byte {
	clean := bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, raw)
	if bytes.HasSuffix(clean, []byte("=")) {
		return clean
	}
	switch len(clean) % 4 {
	case 1:
		return clean[:len(clean)-1]
	case 2:
		return append(clean, "=="...)
	case 3:
		return append(clean, '=')
	}
	return clean
}
