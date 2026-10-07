package pdf

import (
	"strings"
	"testing"
	"testing/iotest"
)

// TestSeekForwardFinalChunkWithEOF covers readers (e.g. FlateDecode) that return their last
// bytes together with io.EOF. seekForward used to stop on that error without positioning
// the buffer, so objects near the end of an object stream were read from the wrong offset.
func TestSeekForwardFinalChunkWithEOF(t *testing.T) {
	data := strings.Repeat("a", 4096) + "XYZ"
	b := newBuffer(iotest.DataErrReader(strings.NewReader(data)), 0)
	b.allowEOF = true
	if c := b.readByte(); c != 'a' {
		t.Fatalf("first byte = %q, want 'a'", c)
	}
	if err := b.seekForward(4097); err != nil {
		t.Fatalf("seekForward: %v", err)
	}
	if c := b.readByte(); c != 'Y' {
		t.Errorf("byte after seekForward(4097) = %q, want 'Y'", c)
	}
}
