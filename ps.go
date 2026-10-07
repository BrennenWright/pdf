// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"fmt"
	"io"
	"strings"
)

// A Stack represents a stack of values.
type Stack struct {
	stack []Value
}

func (stk *Stack) Len() int {
	return len(stk.stack)
}

func (stk *Stack) Push(v Value) {
	stk.stack = append(stk.stack, v)
}

func (stk *Stack) Pop() Value {
	n := len(stk.stack)
	if n == 0 {
		return Value{}
	}
	v := stk.stack[n-1]
	stk.stack[n-1] = Value{}
	stk.stack = stk.stack[:n-1]
	return v
}

func newDict() Value {
	return Value{nil, objptr{}, make(dict)}
}

// Interpret interprets the content in a stream as a basic PostScript program,
// pushing values onto a stack and then calling the do function to execute
// operators. The do function may push or pop values from the stack as needed
// to implement op.
//
// Interpret handles the operators "dict", "currentdict", "begin", "end", "def", and "pop" itself.
//
// Interpret is not a full-blown PostScript interpreter. Its job is to handle the
// very limited PostScript found in certain supporting file formats embedded
// in PDF files, such as cmap files that describe the mapping from font code
// points to Unicode code points.
//
// There is no support for executable blocks, among other limitations.
//
func Interpret(strm Value, do func(stk *Stack, op string)) {
	interpretReader(strm.Reader(), do)
}

// contentStreamReader returns the data of a page's Contents entry, which may be a single
// stream or an array of streams. An array must be read as one stream (PDF 32000-1 §7.8.2):
// producers such as Word split it mid-object, so the font, text state and pending operands
// carry across each boundary. A read error ends only the stream that failed.
func contentStreamReader(contents Value) io.Reader {
	if contents.Kind() != Array {
		return contents.Reader()
	}
	parts := make([]io.Reader, 0, 2*contents.Len())
	for i := 0; i < contents.Len(); i++ {
		parts = append(parts, eofOnErrorReader{contents.Index(i).Reader()}, strings.NewReader("\n"))
	}
	return io.MultiReader(parts...)
}

type eofOnErrorReader struct {
	rd io.Reader
}

func (r eofOnErrorReader) Read(p []byte) (int, error) {
	n, err := r.rd.Read(p)
	if err != nil && err != io.EOF {
		err = io.EOF
	}
	return n, err
}

func interpretReader(rd io.Reader, do func(stk *Stack, op string)) {
	b := newBuffer(rd, 0)
	b.allowEOF = true
	b.allowObjptr = false
	b.allowStream = false
	var stk Stack
	var dicts []dict

Reading:
	for {
		tok := b.readToken()
		if tok == io.EOF {
			break
		}
		if kw, ok := tok.(keyword); ok {
			switch kw {
			case "null", "[", "]", "<<", ">>":
				break
			default:
				for i := len(dicts) - 1; i >= 0; i-- {
					if v, ok := dicts[i][name(kw)]; ok {
						stk.Push(Value{nil, objptr{}, v})
						continue Reading
					}
				}
				do(&stk, string(kw))
				continue
			case "dict":
				stk.Pop()
				stk.Push(Value{nil, objptr{}, make(dict)})
				continue
			case "currentdict":
				if len(dicts) == 0 {
					panic("no current dictionary")
				}
				stk.Push(Value{nil, objptr{}, dicts[len(dicts)-1]})
				continue
			case "begin":
				d := stk.Pop()
				if d.Kind() != Dict {
					panic("cannot begin non-dict")
				}
				dicts = append(dicts, d.data.(dict))
				continue
			case "end":
				if len(dicts) <= 0 {
					panic("mismatched begin/end")
				}
				dicts = dicts[:len(dicts)-1]
				continue
			case "def":
				if len(dicts) <= 0 {
					panic("def without open dict")
				}
				val := stk.Pop()
				key, ok := stk.Pop().data.(name)
				if !ok {
					// Some malformed cmap streams emit "def" with a non-name key.
					// Skip the assignment and continue so text extraction can proceed.
					continue
				}
				dicts[len(dicts)-1][key] = val.data
				continue
			case "pop":
				stk.Pop()
				continue
			}
		}
		b.unreadToken(tok)
		obj, err := b.readObject()
		if err != nil {
			return
		}
		stk.Push(Value{nil, objptr{}, obj})
	}
}

type seqReader struct {
	rd     io.Reader
	offset int64
}

func (r *seqReader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset != r.offset {
		return 0, fmt.Errorf("non-sequential read of stream")
	}
	n, err := io.ReadFull(r.rd, buf)
	r.offset += int64(n)
	return n, err
}
