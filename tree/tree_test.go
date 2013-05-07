// Copyright (c) 2013 Emery Hemingway
// The test vectors are from
// http://web.archive.org/web/20080316033726/http://www.open-content.net/specs/draft-jchapweske-thex-02.html#anchor17

package tree_test

import (
	"bytes"
	"encoding/base32"
	"crypto/sha1"
	"testing"
)

import "code.google.com/p/go-hashtree/tree"

type treeTest struct {
	desc string
	out  string
	in   []byte
}

var golden = []treeTest{}

func init() {
	var out string
	var in []byte

	out = "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ"
	in  = make([]byte, 0)
	golden = append(golden, treeTest{"an empty (zero-length) buffer", out, in})

	
	out = "LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP"
	in  = []byte{byte(0)}
	golden = append(golden, treeTest{"a buffer with a single zero byte", out, in})

	out = "ORWD6TJINRJR4BS6RL3W4CWAQ2EDDRVU"
	in  = make([]byte, 0, 1024)
	for i := 0; i < 1024; i++ {
		in = append(in, byte('A'))
	}
	golden = append(golden, treeTest{"a buffer with 1024 'A' characters", out, in})
	

	out = "UUHHSQPHQXN5X6EMYK6CD7IJ7BHZTE77"
	in  = make([]byte, 0, 1025)
	for i := 0; i < 1025; i++ {
		in = append(in, byte('A'))
	}
	golden = append(golden, treeTest{"a buffer with 1025 'A' characters", out, in})
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		base := sha1.New()
		tree := tree.New(sha1.New())
		for j := 0; j < 4; j++ {
			base.Write(g.in)
			leaf := base.Sum(nil)
			tree.Write(leaf)

			s := base32.StdEncoding.EncodeToString(tree.Sum(nil))
			if s != g.out {
				t.Fatalf("sha1 tree[%d](%s) = %s want %s", j, g.desc, s, g.out)
			}
			base.Reset()
			tree.Reset()
		}
	}
}

func BenchMarkGolder(b *testing.B) {
	b.StopTimer()
	base := sha1.New()
	tree := tree.New(base)
	var buf bytes.Buffer
	for _, g := range golden {
		buf.Write([]byte(g.in))
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		tree.Write(buf.Bytes())
	}
}