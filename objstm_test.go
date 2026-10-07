package pdf

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// buildObjStmPDF returns a PDF whose objects 4 and 5 live in a FlateDecode object stream
// (object 3), located through an uncompressed xref stream (object 6). Object 4 is a long
// string so that object 5 sits past the first 4096 decoded bytes.
func buildObjStmPDF(t *testing.T) []byte {
	t.Helper()
	obj4 := "(" + strings.Repeat("a", 5000) + ")"
	obj5 := "<< /Marker /Found >>"
	header := fmt.Sprintf("4 0 5 %d ", len(obj4)+1)
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(header + obj4 + " " + obj5))
	zw.Close()

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	writeObj := func(id int, body string) {
		offsets[id] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", id, body)
	}
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [] /Count 0 >>")
	offsets[3] = b.Len()
	fmt.Fprintf(&b, "3 0 obj\n<< /Type /ObjStm /N 2 /First %d /Filter /FlateDecode /Length %d >>\nstream\n", len(header), z.Len())
	b.Write(z.Bytes())
	b.WriteString("\nendstream\nendobj\n")

	row := func(typ byte, f2 uint32, f3 uint16) []byte {
		r := []byte{typ, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(r[1:5], f2)
		binary.BigEndian.PutUint16(r[5:7], f3)
		return r
	}
	xrefOff := b.Len()
	var rows []byte
	rows = append(rows, row(0, 0, 65535)...)
	for id := 1; id <= 3; id++ {
		rows = append(rows, row(1, uint32(offsets[id]), 0)...)
	}
	rows = append(rows, row(2, 3, 0)...)
	rows = append(rows, row(2, 3, 1)...)
	rows = append(rows, row(1, uint32(xrefOff), 0)...)
	fmt.Fprintf(&b, "6 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n", len(rows))
	b.Write(rows)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefOff)
	return b.Bytes()
}

func TestObjectStreamResolvesObjectsPastFirstChunk(t *testing.T) {
	src := buildObjStmPDF(t)
	r, err := NewReader(bytes.NewReader(src), int64(len(src)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	for i := 0; i < 2; i++ { // second pass is served from the decoded-stream cache
		if got := r.resolve(objptr{}, objptr{id: 5}).Key("Marker").Name(); got != "Found" {
			t.Errorf("pass %d: object 5 /Marker = %q, want Found", i+1, got)
		}
		if got := len(r.resolve(objptr{}, objptr{id: 4}).RawString()); got != 5000 {
			t.Errorf("pass %d: object 4 length = %d, want 5000", i+1, got)
		}
	}
	if len(r.objStmCache) != 1 {
		t.Errorf("object streams decoded = %d, want 1", len(r.objStmCache))
	}
}
