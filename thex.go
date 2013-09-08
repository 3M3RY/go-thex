// Copyright © 2013 Emery Hemingway
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package thex implements hash tree computation as defined in the following:
// http://web.archive.org/web/20080316033726/http://www.open-content.net/specs/draft-jchapweske-thex-02.html
// R. C. Merkle, A digital signature based on a conventional encryption function, Crypto '87
//
// thex is hash algorithm agnostic, New returns a new hash.Hash interface
// with a the hash.Hash argument as the internal algorithm.
//
// Do not directly pass the data being hashed, write data chunks prepended with a 
// 0x00 byte to an external hash function, and write the resulting digests to the 
// tree. The recommended chunk size is 1024 bytes.
//
// thex prepends each leaf hash with an 0x01 byte. This is to decrease the chance
// of collisions between external hashes and internal node hashes.
//
// Because Write takes hash digests rather than chunks of data, intermediate
// node levels may be verified as well, Just write a complete row of intermediate 
// node digests and call Sum().
package thex

import (
	"hash"
	"sync"
)

var innerPrefix = []byte{byte(1)}

type tree struct {
	digest   hash.Hash
	mu       sync.Mutex // protects digest when GOMAXPROCS > 1
	size     int
	overflow []byte
	leaves   chan []byte
	sum      chan []byte
}

// New returns a new hash.Hash that computes the root of a
// row of tree leaves. The digest argument is the hash.Hash
// that will be used to process the tree.
func New(digest hash.Hash) hash.Hash {
	t := &tree{
		digest: digest,
		size:   digest.Size(),
	}
	t.Reset()
	return t
}

func (t *tree) BlockSize() int { return t.size }
func (t *tree) Size() int      { return t.size }

// Write accepts serialized leaf stream, where a leaf is one hash.
// If an incomplete leaf is passed, passthe rest in the next Write call.
func (t *tree) Write(p []byte) (n int, err error) {
	n = len(p)
	var i int
	var j int

	// fill up overflow from the last Write
	if len(t.overflow) > 0 {
		i = t.size - len(t.overflow)
		if i > n {
			t.overflow = append(t.overflow, p[:]...)
		} else {
			t.leaves <- append(t.overflow, p[:i]...)
			t.overflow = nil
		}
	}

	j = i + t.size
	for j <= n {
		t.leaves <- p[i:j]
		i = j
		j += t.size
	}
	if i < n {
		t.overflow = p[i:]
	}
	return
}

func (t *tree) Reset() {
	t.overflow = make([]byte, 0, t.size-1)
	t.leaves = make(chan []byte) // Buffering this channel has mixed results on speed
	t.sum = make(chan []byte)
	go t.processLevel(t.leaves, t.sum)
}

func (t *tree) Sum(b []byte) []byte {
	t.leaves <- nil
	return <-t.sum
}

// If it was possible to for tree to hold multiple instances of a Hash
// then the multiple levels could be hashed simultaneously, if the
// channels were buffered and the mutex loosened (I think). -EH
func (t *tree) processLevel(ingress chan []byte, final chan []byte) {
	var left []byte
	var right []byte
	var egress chan []byte
	var sum []byte
	left = <-ingress
	for right = range ingress {
		if right == nil {
			final <- left
		} else {
			egress = make(chan []byte)
			go t.processLevel(egress, final)
			
			t.mu.Lock()
			t.digest.Reset()
			t.digest.Write(innerPrefix)
			t.digest.Write(left)
			t.digest.Write(right)
			sum = t.digest.Sum(nil)
			t.mu.Unlock()
			egress <- sum
			break
		}
	}

	for left = range ingress {
		if left != nil {
			right := <-ingress
			if right != nil {
				t.mu.Lock()
				t.digest.Reset()
				t.digest.Write(innerPrefix)
				t.digest.Write(left)
				t.digest.Write(right)
				sum = t.digest.Sum(nil)
				t.mu.Unlock()
				egress <- sum
			} else {
				egress <- left
				egress <- nil
			}
		} else {
			egress <- nil
		}
	}
}
