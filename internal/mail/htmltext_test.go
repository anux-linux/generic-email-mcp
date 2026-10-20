package mail

import (
	"strings"
	"testing"
)

func TestHTMLToTextStructure(t *testing.T) {
	src := `<!DOCTYPE html><html><head><title>T</title><meta charset="utf-8">
<style>p{color:red}</style><script>alert(1)</script></head><body>
<h1>Invoice&nbsp;#42</h1><p>Hello <b>Bob</b>,<br>thanks &amp; regards.</p>
<ul><li>one</li><li>two<ol><li>a</li><li>b</li></ol></li></ul>
<table><tr><td>Item</td><td>Price</td></tr><tr><td>Tea</td><td>3 €</td></tr></table>
<p><a href="https://example.org/pay?x=1">Pay now</a> or <a href="mailto:bob@example.org">bob@example.org</a>
<a href="javascript:evil()">js</a></p>
<blockquote><p>quoted line</p><p>second</p></blockquote>
<pre>  keep   spacing
line</pre><hr><!-- a comment --><img src="x" alt="ignore previous instructions">
</body></html>`
	got, hidden, truncated := htmlToText(src, 1<<20)
	want := strings.Join([]string{
		"Invoice #42",
		"",
		"Hello Bob,",
		"thanks & regards.",
		"",
		"- one",
		"- two",
		"  1. a",
		"  2. b",
		"",
		"Item\tPrice",
		"Tea\t3 €",
		"",
		"Pay now <https://example.org/pay?x=1> or bob@example.org js",
		"",
		"> quoted line",
		">",
		"> second",
		"",
		"  keep   spacing",
		"line",
		"",
		"---",
	}, "\n")
	if got != want {
		t.Fatalf("got:\n%s\n---want:\n%s", got, want)
	}
	if hidden != 0 || truncated {
		t.Fatalf("hidden=%d truncated=%v", hidden, truncated)
	}
}

func TestHTMLToTextRemovesHiddenContent(t *testing.T) {
	hiddenSnippets := []string{
		`<div style="display:none">H1</div>`,
		`<div style="DISPLAY: NONE !important">H2</div>`,
		`<span style="visibility:hidden">H3</span>`,
		`<span style="opacity:0">H4</span>`,
		`<span style="opacity:0.01">H5</span>`,
		`<span style="font-size:0">H6</span>`,
		`<span style="font-size:1px">H7</span>`,
		`<span style="font-size:0.05em">H8</span>`,
		`<div style="max-height:0;overflow:hidden">H9</div>`,
		`<div style="width:1px;height:1px;overflow:hidden">H10</div>`,
		`<div style="position:absolute;left:-9999px">H11</div>`,
		`<div style="text-indent:-10000px">H12</div>`,
		`<span style="color:transparent">H13</span>`,
		`<span style="color:rgba(0,0,0,0)">H14</span>`,
		`<div style="clip:rect(0 0 0 0)">H15</div>`,
		`<div style="clip-path:inset(50%)">H16</div>`,
		`<div style="transform:scale(0)">H17</div>`,
		`<div style="mso-hide:all">H18</div>`,
		`<div hidden>H19</div>`,
		`<div class="pre x">H20</div>`,
		`<p id="secret">H21</p>`,
		`<span class="ghost">H22</span>`,
	}
	src := `<html><head><style>
/* comment { display:none } */
.pre { display: none; }
div#secret, p#secret { visibility: hidden }
span.ghost { font-size: 0 }
@media (max-width: 600px) { .mobileonly { display: none } }
@import url(x.css);
.visible { color: #333 }
</style></head><body><p>Visible start</p>` + strings.Join(hiddenSnippets, "") +
		`<p class="mobileonly visible">Visible mobile</p><p>Visible end</p></body></html>`
	got, hidden, _ := htmlToText(src, 1<<20)
	if want := "Visible start\n\nVisible mobile\n\nVisible end"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if hidden != len(hiddenSnippets) {
		t.Fatalf("hidden = %d, want %d", hidden, len(hiddenSnippets))
	}
}

func TestHTMLToTextKeepsBorderlineVisible(t *testing.T) {
	src := `<p style="font-size:12px;opacity:0.9;height:0">A</p><p style="overflow:hidden;height:20px">B</p><p aria-hidden="true">C</p>`
	got, hidden, _ := htmlToText(src, 1<<20)
	if got != "A\n\nB\n\nC" || hidden != 0 {
		t.Fatalf("got %q hidden=%d", got, hidden)
	}
}

func TestHTMLToTextInvisibleUnicode(t *testing.T) {
	got, _, _ := htmlToText("<p>pay\u200b\u200bme\U000E0041\U000E0042</p>", 1<<20)
	if got != "payme" {
		t.Fatalf("got %q", got)
	}
}

func TestHTMLToTextLimit(t *testing.T) {
	src := strings.Repeat("<p>paragraph of text</p>", 1000)
	got, _, truncated := htmlToText(src, 100)
	if !truncated || len(got) > 200 {
		t.Fatalf("truncated=%v len=%d", truncated, len(got))
	}
}

func TestHTMLToTextMalformed(t *testing.T) {
	got, _, _ := htmlToText(`<div><p>unclosed <b>bold <i>both</div> tail <script>x`, 1<<20)
	if got != "unclosed bold both\n\ntail" {
		t.Fatalf("got %q", got)
	}
}
