package mail

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func single(typ, sub string, params map[string]string, disp *imap.BodyStructureDisposition) *imap.BodyStructureSinglePart {
	return &imap.BodyStructureSinglePart{
		Type: typ, Subtype: sub, Params: params, Encoding: "7bit", Size: 1000,
		Extended: &imap.BodyStructureSinglePartExt{Disposition: disp},
	}
}

func multi(sub string, children ...imap.BodyStructure) *imap.BodyStructureMultiPart {
	return &imap.BodyStructureMultiPart{Subtype: sub, Children: children}
}

func paths(p bodyPlan) (texts []string, atts []string) {
	for _, t := range p.texts {
		kind := "plain"
		if t.html {
			kind = "html"
		}
		texts = append(texts, formatPart(t.path)+":"+kind)
	}
	for _, a := range p.attachments {
		atts = append(atts, a.Part+":"+a.ContentType)
	}
	return texts, atts
}

func TestPlanBody(t *testing.T) {
	plain := func() *imap.BodyStructureSinglePart {
		return single("TEXT", "PLAIN", map[string]string{"charset": "utf-8"}, nil)
	}
	html := func() *imap.BodyStructureSinglePart { return single("text", "html", nil, nil) }
	pdf := single("application", "pdf", map[string]string{"name": "a.pdf"}, &imap.BodyStructureDisposition{Value: "attachment", Params: map[string]string{"filename": "a.pdf"}})
	img := single("image", "png", nil, &imap.BodyStructureDisposition{Value: "inline"})
	txtAttachment := single("text", "plain", nil, &imap.BodyStructureDisposition{Value: "attachment", Params: map[string]string{"filename": "notes.txt"}})
	namedTxt := single("text", "plain", map[string]string{"name": "log.txt"}, nil)
	rfc822 := &imap.BodyStructureSinglePart{Type: "message", Subtype: "rfc822", Size: 500,
		MessageRFC822: &imap.BodyStructureMessageRFC822{Envelope: &imap.Envelope{Subject: "Fwd original"}}}

	cases := []struct {
		name  string
		bs    imap.BodyStructure
		texts []string
		atts  []string
	}{
		{"single plain", plain(), []string{"1:plain"}, nil},
		{"single html", html(), []string{"1:html"}, nil},
		{"alternative prefers plain", multi("alternative", plain(), html()), []string{"1:plain"}, nil},
		{"alternative plain last", multi("ALTERNATIVE", html(), plain()), []string{"2:plain"}, nil},
		{"alternative html only", multi("alternative", html()), []string{"1:html"}, nil},
		{"mixed with attachment", multi("mixed", multi("alternative", plain(), html()), pdf), []string{"1.1:plain"}, []string{"2:application/pdf"}},
		{"related html with inline image", multi("related", html(), img), []string{"1:html"}, []string{"2:image/png"}},
		{"alternative into related", multi("alternative", plain(), multi("related", html(), img)), []string{"1:plain"}, nil},
		{"text attachment is not body", multi("mixed", plain(), txtAttachment, namedTxt), []string{"1:plain"}, []string{"2:text/plain", "3:text/plain"}},
		{"forwarded message", multi("mixed", plain(), rfc822), []string{"1:plain"}, []string{"2:message/rfc822"}},
		{"inline parts in mixed", multi("mixed", plain(), img, plain()), []string{"1:plain", "3:plain"}, []string{"2:image/png"}},
		{"no body", pdf, nil, []string{"1:application/pdf"}},
		{"text part cap", multi("mixed", plain(), plain(), plain(), plain(), plain(), plain(), plain(), plain(), plain(), plain()),
			[]string{"1:plain", "2:plain", "3:plain", "4:plain", "5:plain", "6:plain", "7:plain", "8:plain"}, nil},
	}
	for _, tc := range cases {
		texts, atts := paths(planBody(tc.bs))
		if !reflect.DeepEqual(texts, tc.texts) || !reflect.DeepEqual(atts, tc.atts) {
			t.Errorf("%s: texts=%v atts=%v, want %v %v", tc.name, texts, atts, tc.texts, tc.atts)
		}
	}
}

func TestAttachmentMetadata(t *testing.T) {
	b64part := &imap.BodyStructureSinglePart{
		Type: "application", Subtype: "pdf", Encoding: "base64", Size: 4000,
		Params: map[string]string{"name": "fallback.pdf"},
		Extended: &imap.BodyStructureSinglePartExt{Disposition: &imap.BodyStructureDisposition{
			Value:  "attachment",
			Params: map[string]string{"filename*": "utf-8''R%C3%A9sum%C3%A9%E2%80%8B.pdf"},
		}},
	}
	a := attachmentOf([]int{2}, b64part)
	want := Attachment{Part: "2", Filename: "Résumé.pdf", ContentType: "application/pdf", Size: 3000}
	if a != want {
		t.Fatalf("got %+v, want %+v", a, want)
	}

	cont := &imap.BodyStructureSinglePart{
		Type: "image", Subtype: "jpeg", ID: "<cid1>",
		Params: map[string]string{"name*0": "very-long-", "name*1": "name.jpg"},
	}
	a = attachmentOf([]int{1, 2}, cont)
	if a.Filename != "very-long-name.jpg" || !a.Inline || a.Part != "1.2" {
		t.Fatalf("continuation: %+v", a)
	}

	evil := single("application", "octet-stream", map[string]string{"name": "a\r\nb\u202egpj.exe"}, nil)
	if a = attachmentOf([]int{3}, evil); a.Filename != "a bgpj.exe" {
		t.Fatalf("filename not sanitized: %q", a.Filename)
	}
}

func TestDecodeTextPart(t *testing.T) {
	latin1 := []byte("Gr\xfc\xdfe aus K\xf6ln")
	cases := []struct {
		name string
		tp   textPart
		raw  []byte
		want string
	}{
		{"base64 iso-8859-1", textPart{charset: "ISO-8859-1", encoding: "base64"}, []byte(base64.StdEncoding.EncodeToString(latin1)), "Grüße aus Köln"},
		{"qp windows-1252", textPart{charset: "windows-1252", encoding: "quoted-printable"}, []byte("Preis: 5 =80, =\r\nweiter"), "Preis: 5 €, weiter"},
		{"8bit utf-8", textPart{charset: "utf-8", encoding: "8bit"}, []byte("Grüße"), "Grüße"},
		{"no charset latin1 bytes", textPart{encoding: "8bit"}, latin1, "Grüße aus Köln"},
		{"unknown charset", textPart{charset: "x-made-up", encoding: "7bit"}, []byte("plain ascii"), "plain ascii"},
		{"unknown encoding", textPart{charset: "utf-8", encoding: "x-uuencode"}, []byte("raw"), "raw"},
		{"truncated base64", textPart{charset: "utf-8", encoding: "base64"}, []byte(base64.StdEncoding.EncodeToString([]byte("hello world"))[:7]), "hello"},
		{"base64 with line breaks", textPart{charset: "utf-8", encoding: "BASE64"}, []byte("aGVs\r\nbG8=\r\n"), "hello"},
		{"html part", textPart{html: true, charset: "utf-8", encoding: "7bit"}, []byte("<p>x</p>"), "<p>x</p>"},
	}
	for _, tc := range cases {
		if got := decodeTextPart(tc.tp, tc.raw); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
