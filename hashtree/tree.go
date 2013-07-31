// Package tree implements hash tree computation as defined in the following:
// http://web.archive.org/web/20080316033726/http://www.open-content.net/specs/draft-jchapweske-thex-02.html
// R. C. Merkle, A digital signature based on a conventional encryption function, Crypto '87
//
// tree is hash algorithm agnostic, New returns a new hash.Hash interface 
// with a the hash.Hash argument as the internal algorithm.
//
// Do not pass the data you wish to build a tree out of to Write.
// Hash the source data in chunks and then pass those chunks to Write.
// The recommended chunk size is 1024 bytes.
//
// Do note that this implementation follows the Tree Hash EXchange format
// recommendation and prepends each leaf hash with a zero byte. This is to
// decrease the collision rate between external chunk hashes and internal 
// leaf hashes. Be aware this policy may be different from other tree specs.
//
// Because Write takes hash leaves rather than chunks of data, intermediate
// leaf levels may be verified.
package tree

import (
	"hash"
)

var innerPrefix = []byte{byte(1)}

type tree struct {
	digest   hash.Hash
	size     int
	overflow []byte
	leaves   chan []byte
	sum      chan []byte
}

// New returns a new hash.Hash that computes the root of a 
// row of tree leaves. The digest argument is the hash.Hash
// that will be used to process the tree.
func New(digest hash.Hash) hash.Hash {
	size := digest.Size()
	t := &tree{
		digest: digest,
		size:   size,
	}
	t.Reset()
	return t
}

func (t *tree) Size() int {
	return t.size
}

func (t *tree) BlockSize() int {
	return t.size
}

// Write accepts serialized leaves of a hash tree, where a leaf is
// one hash. If an incomplete leaf is passed in a single Write, it 
// will be completed with the next Write.
func (t *tree) Write(p []byte) (nn int, err error) {
	nn = len(p)
	var i int
	var j int
	if len(t.overflow) > 0 {
		i := t.size - len(t.overflow)
		t.leaves <- append(t.overflow, p[:i]...)
		t.overflow = nil
	}
	j = i + t.size
	for j <= nn {
		t.leaves <- p[i:j]
		i = j
		j += t.size
	}
	if i < nn {
		t.overflow = p[i:]
	}
	return nn, nil
}

func (t *tree) Reset() {
	t.overflow  = make([]byte, 0, t.size - 1)
	t.leaves = make(chan []byte) // Buffering this channel has mixed results on speed
	t.sum   = make(chan []byte)
	go t.processLevel(t.leaves, t.sum)
}

func (t *tree) Sum(b []byte) []byte {
	t.leaves <- nil
	return <- t.sum
}

// If it was possible to for tree to hold multiple instances of a Hash
// then the multiple levels could be hashed simultaneously, if the 
// channels were buffered
func (t *tree) processLevel(ingress chan []byte, final chan []byte) {
	var left []byte
	var right []byte
	var egress chan []byte
	left = <-ingress
	for right = range ingress {
		if right == nil {
			final <- left
		} else {
			egress = make(chan []byte)
			go t.processLevel(egress, final)

			t.digest.Reset()
			t.digest.Write(innerPrefix)
			t.digest.Write(left)
			t.digest.Write(right)
			egress <- t.digest.Sum(nil)
			break
		}
	}

	for left = range ingress {
		if left != nil {
			right := <-ingress
			if right != nil {
				t.digest.Reset()
				t.digest.Write(innerPrefix)
				t.digest.Write(left)
				t.digest.Write(right)
				egress <- t.digest.Sum(nil)
			} else {
				egress <- left
				egress <- nil
			}
		} else {
			egress <- nil
		}
	}
}
