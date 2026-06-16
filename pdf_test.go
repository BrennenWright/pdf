package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var referenceFirstPage = `TEST FILE 
 
Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam 
nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam 
erat, sed diam voluptua. At vero eos et accusam et 
TEST 
SUBTITLE`

var referenceFirstPageWithAddLine = `TEST FILE 
 
Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam 
nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam 
erat, sed diam voluptua. At vero eos et accusam et
 
TEST 
SUBTITLE`

// TestCryptKeyTruncation verifies that cryptKey truncates its output to
// min(len(fileKey)+5, 16) bytes as required by PDF 32000-1:2008 §7.6.3.3 step 4.
//
// Previously cryptKey returned the full 16-byte MD5 digest regardless of the
// file key length. For 40-bit RC4 encryption (5-byte file key) the correct
// per-object key is 10 bytes; using 16 bytes produces a completely wrong
// RC4 keystream, causing all object stream decryptions to fail silently with
// garbage output and manifesting as "cannot find object in stream" panics.
//
// The bug went undetected because 128-bit RC4 files happen to need all 16
// bytes (min(21, 16) = 16), so only sub-128-bit encrypted PDFs were affected.
// TestPDF20HeaderAccepted verifies that NewReaderEncrypted accepts a %PDF-2.0 header.
// The previous check (HasPrefix("%PDF-1.")) rejected all PDF 2.0+ files with
// "not a PDF file: invalid header" despite them being structurally valid.
func TestPDF20HeaderAccepted(t *testing.T) {
	// Build a minimal byte slice with a %PDF-2.0 header, a well-formed %%EOF,
	// and a startxref. We only need the header check to pass; the reader will
	// fail later when it cannot find a valid xref, but that is a different error.
	src := []byte("%PDF-2.0\n%%EOF\n")
	r := bytes.NewReader(src)
	_, err := NewReader(r, int64(len(src)))
	// Any error other than the old "invalid header" rejection is acceptable —
	// the file is intentionally not a complete PDF.
	if err != nil && bytes.Contains([]byte(err.Error()), []byte("invalid header")) {
		t.Errorf("NewReader rejected %%PDF-2.0 header: %v", err)
	}
}

// TestAESStringDecryption verifies that decryptString no longer panics when
// useAES is true. Previously it contained an unimplemented stub:
//
//	panic("AES not implemented")
//
// PDF 32000-1:2008 §7.6.5 specifies AES-encrypted strings have the same
// layout as streams: a 16-byte IV followed by AES-CBC ciphertext with PKCS#7
// padding. V=4 R=4 PDFs (AESV2, /StrF /StdCF) encrypt all string tokens via
// this path; the panic surfaced on the first string encountered during parsing.
func TestAESStringDecryption(t *testing.T) {
	// Construct a known AES-128-CBC ciphertext for the string "hello" and
	// verify decryptString round-trips it correctly.
	import_key := make([]byte, 16) // all-zero file key for test
	ptr := objptr{id: 1, gen: 0}

	// Encrypt "hello" + PKCS#7 padding (11 bytes pad to reach 16) with a
	// known IV so we can assert the plaintext coming back.
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plaintext := []byte("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b") // 16 bytes with PKCS#7

	perObjKey := cryptKey(import_key, true, ptr)
	cb, _ := aes.NewCipher(perObjKey)
	ciphertext := make([]byte, 16)
	cipher.NewCBCEncrypter(cb, iv).CryptBlocks(ciphertext, plaintext)

	input := string(append(iv, ciphertext...))
	got := decryptString(import_key, true, ptr, input)
	if got != "hello" {
		t.Errorf("decryptString AES: got %q, want %q", got, "hello")
	}
}

func TestCryptKeyTruncation(t *testing.T) {
	ptr := objptr{id: 7874, gen: 0}

	cases := []struct {
		fileKeyLen  int
		wantKeyLen  int
	}{
		{5, 10},  // RC4-40:  min(5+5, 16) = 10
		{7, 12},  // RC4-56:  min(7+5, 16) = 12
		{10, 15}, // RC4-80:  min(10+5, 16) = 15
		{11, 16}, // RC4-88:  min(11+5, 16) = 16 (capped)
		{16, 16}, // RC4-128: min(16+5, 16) = 16 (capped)
	}

	for _, tc := range cases {
		key := make([]byte, tc.fileKeyLen)
		got := cryptKey(key, false, ptr)
		if len(got) != tc.wantKeyLen {
			t.Errorf("cryptKey(%d-byte key): got %d bytes, want %d", tc.fileKeyLen, len(got), tc.wantKeyLen)
		}
	}
}

//
// this pdf has an object within stream which is handled different!
// the original implementation calculated the stream but didn't returned the object at resolve
//
// @todo: there is an empty line added, still don't know where
//
func Test_ReadPdf_v17_linarized_xrefStream(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1601712620132-32_Print-Adobe__pdf15_linarized_xrefStream.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect numPage .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPageWithAddLine != content {
		t.Error("Asser: content different from reference:")
		t.Error(content)
	}
}
func Test_ReadPdf_v17_linarized_xref(t *testing.T) {

	testFile := "./testdata/story_avepdf-com__pdf17_linarized_xref.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect numPage .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference:")
		t.Error(content)
	}
}
//
// this pdf has an array of refs at /Contents
//	standard:
// page = {<</Contents 4 0 R /Group <</CS /DeviceRGB /S /Transparency /Type /Group>> /MediaBox [0 0 612 792] /Parent 2 0 R /Resources <</ExtGState <</GS7 7 0 R /GS8 8 0 R>> /Font <</F1 5 0 R /F2 9 0 R /F3 11 0 R>> /ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>> /StructParents 0 /Type /Page>>}
//	deviation:
// page = {<</Contents [20 0 R] /CropBox [0 0 595.32001 841.92004] /MediaBox [0 0 595.32001 841.92004] /Parent 2 0 R /Resources 21 0 R /Rotate 0 /Type /Page>>}
//
func Test_ReadPdf_v17_trailer_arrayAtPageContents(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1712620132_Print-Microsoft__pdf17_trailer_array-at-page-contents.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect numPage .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference:")
		t.Error(content)
	}
}
func Test_ReadPdf_v17_StandardPDFA_trailer(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1712620132_SaveAs-Standard-PDFA__pdf17_trailer.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect numPage .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference:")
		t.Error(content)
	}
}
func Test_ReadPdf_v17_MinSizePDFA_trailer(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1712620132_SaveAs-MinSize-PDFA__pdf17_trailer.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect if totalPages != 5 { .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference")
		t.Error(content)
	}
}
func Test_ReadPdf_v17_StandardNoPDFA_2trailer(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1712620132_SaveAs-Standard-NoPDFA__pdf17_2trailer.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect totalPages .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference")
		t.Error(content)
	}
}
func Test_ReadPdf_v17_MinSizeNoPDFA_2trailer(t *testing.T) {

	testFile := "./testdata/story_Word2019-2312-1712620132_SaveAs-MinSize-NoPDFA__pdf17_2trailer.pdf"
	totalPages, content := readPdfAndGetFirstPageAsText(testFile)
	if totalPages != 5 {
		t.Error("Asser: incorrect totalPages .. want=5 <> got " + strconv.Itoa(totalPages))
	}
	if referenceFirstPage != content {
		t.Error("Asser: content different from reference")
		t.Error(content)
	}
}
//
// read pdf and return content of first page for quick check
//
func readPdfAndGetFirstPageAsText(fileName string) (totalPages int, content string) {
	fmt.Println("read file = " + fileName)
	
	f, err := Open(fileName)
	if err != nil {
		return 0, err.Error()
	}

	totalPages = f.NumPage()
	if totalPages == 0 {
		return totalPages, content
	} else {
	
		var buf bytes.Buffer
		p := f.Page(1)
		texts := p.Content().Text
		var lastY = 0.0
		line := ""

		for _, text := range texts {
			if lastY != text.Y {
				if lastY > 0 {
					buf.WriteString(line + "\n")
					line = text.S
				} else {
					line += text.S
				}
			} else {
				line += text.S
			}

			lastY = text.Y
		}
		buf.WriteString(line)
		content = strings.TrimSpace(buf.String())
	}
	
	return totalPages, content
}
//
// process all pdfs within ./testdata/*.pdf and write content to *.txt
//
func Test_WalkDirectory_ReadPdfs(t *testing.T) {
	
	// get files
	var startPath string = "./testdata"
	files, err := walkDir(startPath, ".pdf")
	if err != nil {
        t.Error("Assert: " + err.Error())
    }
	
	// read files
	for i:=0; i<len(files); i++ {
		
		testFile := files[i]
		if !strings.HasSuffix(testFile, ".pdf") {
			continue
		}
		
fmt.Println(". open testFile = ", testFile)
		f, err := Open(testFile)
		if err != nil {
			t.Error(err)
		}

		totalPage := f.NumPage()
fmt.Println(". totalPage = ", totalPage)
		
		var buf bytes.Buffer

		for pageIndex := 1; pageIndex <= totalPage; pageIndex++ {
		
			p := f.Page(pageIndex)
			if p.V.IsNull() {
				continue
			}
			
			texts := p.Content().Text
			var lastY = 0.0
			line := ""

			for _, text := range texts {
				if lastY != text.Y {
					if lastY > 0 {
						buf.WriteString(line + "\n")
						line = text.S
					} else {
						line += text.S
					}
				} else {
					line += text.S
				}

				lastY = text.Y
			}
			buf.WriteString(line)
		}
		
		//
		//fmt.Println(buf.String())
		
		//
		// write bytes buffer to txt-file
		writeToFileName := strings.Replace(testFile, ".pdf", ".txt", -1)
		fmt.Println(".. writeToFileName = ", writeToFileName)
		
		fw, err := os.Create(writeToFileName)
		if err != nil {
			t.Error(err)
		}
		_, err = fw.WriteString(buf.String())
		if err != nil {
			t.Error(err)
		}
		
		fw.Close()
	}
}
//
// walk indicated directory and 
// return all file.names with indicated suffix
//
func walkDir(root, fileSuffix string) ([]string, error) {
    var files []string
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if !info.IsDir() && strings.HasSuffix(path, fileSuffix) {
            files = append(files, path)
        }
        return nil
    })
    return files, err
}