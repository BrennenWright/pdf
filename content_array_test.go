package pdf

import (
	"bytes"
	"fmt"
	"testing"
)

// buildTestPDF assembles a one-page PDF whose page /Contents is an array of the given
// content streams. Font /F1 maps codes A and B to x and y, so text decoded without the
// font comes back as A/B instead of x/y. Font /F2 maps A and B to p and q.
func buildTestPDF(streams []string) []byte {
	var objs []string
	contentRefs := ""
	for i := range streams {
		contentRefs += fmt.Sprintf("%d 0 R ", 6+i)
	}
	objs = append(objs,
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents ["+contentRefs+"] >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [65 /x /y] >> >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding << /Differences [65 /p /q] >> >>",
	)
	for _, s := range streams {
		objs = append(objs, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(s)+1, s))
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// TestContentArraySharesStateAcrossStreams covers Word-produced pages whose /Contents
// array is split mid-object: the font is set in one stream and used in the next, TD's
// operands and TJ's array end one stream while the operator starts the next.
func TestContentArraySharesStateAcrossStreams(t *testing.T) {
	src := buildTestPDF([]string{
		"BT /F1 12 Tf 72 700 Td",
		"(AB) Tj 0 -14",
		"TD [(BA)]",
		"TJ ET",
	})
	r, err := NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	var got string
	for _, tx := range r.Page(1).Content().Text {
		if tx.Font != "Helvetica" {
			t.Errorf("char %q has font %q, want Helvetica", tx.S, tx.Font)
		}
		got += tx.S
	}
	if got != "xyyx" {
		t.Errorf("Content text = %q, want %q", got, "xyyx")
	}

	plain, err := r.Page(1).GetPlainText(nil)
	if err != nil {
		t.Fatalf("GetPlainText: %v", err)
	}
	if plain != "xyyx" {
		t.Errorf("GetPlainText = %q, want %q", plain, "xyyx")
	}
}

// TestContentRestoreRestoresFontEncoding covers a font set inside q ... Q: after Q the
// outer font and its encoding apply again, not the inner font's encoding.
func TestContentRestoreRestoresFontEncoding(t *testing.T) {
	src := buildTestPDF([]string{
		"BT /F1 12 Tf 72 700 Td (A) Tj ET q BT /F2 12 Tf (A) Tj ET Q",
		"BT (B) Tj ET",
	})
	r, err := NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	var got, fonts string
	for _, tx := range r.Page(1).Content().Text {
		got += tx.S
		fonts += tx.Font + " "
	}
	if got != "xpy" {
		t.Errorf("Content text = %q (fonts %s), want %q", got, fonts, "xpy")
	}
}
