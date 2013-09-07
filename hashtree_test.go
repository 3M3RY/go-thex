// The test vectors are from
// http://web.archive.org/web/20080316033726/http://www.open-content.net/specs/draft-jchapweske-thex-02.html#anchor17

package hashtree_test

import (
	"crypto/sha1"
	"encoding/base32"
	"github.com/3M3RY/go-hashtree"
	"math/rand"
	"testing"
	"time"
)

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
	in = make([]byte, 0)
	golden = append(golden, treeTest{"an empty (zero-length) buffer", out, in})

	out = "LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP"
	in = []byte{byte(0)}
	golden = append(golden, treeTest{"a buffer with a single zero byte", out, in})

	out = "ORWD6TJINRJR4BS6RL3W4CWAQ2EDDRVU"
	in = make([]byte, 1024)
	for i := 0; i < 1024; i++ {
		in[i] = byte('A')
	}
	golden = append(golden, treeTest{"a buffer with 1024 'A' characters", out, in})

	out = "UUHHSQPHQXN5X6EMYK6CD7IJ7BHZTE77"
	in = make([]byte, 1025)
	for i := 0; i < 1025; i++ {
		in[i] = byte('A')
	}
	golden = append(golden, treeTest{"a buffer with 1025 'A' characters", out, in})
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		base := sha1.New()
		tree := hashtree.New(sha1.New())
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

func BenchmarkGolden(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	byt := byte(rand.Int())
	l := b.N
	buf := make([]byte, l)
	for i := 0; i < l; i++ {
		buf[i] = byt
	}

	base := sha1.New()
	t := hashtree.New(base)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Write(buf)
	}
}
