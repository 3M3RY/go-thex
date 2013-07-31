PACKAGE DOCUMENTATION

package tree
    import "github.com/3M3RY/go-hashtree/hashtree"

    Package tree implements hash tree computation as defined in the
    following:
    http://web.archive.org/web/20080316033726/http://www.open-content.net/specs/draft-jchapweske-thex-02.html
    R. C. Merkle, A digital signature based on a conventional encryption
    function, Crypto '87

    tree is hash algorithm agnostic, New returns a new hash.Hash interface
    with a the hash.Hash argument as the internal algorithm.

    Do not pass the data you wish to build a tree out of to Write. Hash the
    source data in chunks and then pass those chunks to Write. The
    recommended chunk size is 1024 bytes.

    Do note that this implementation follows the Tree Hash EXchange format
    recommendation and prepends each leaf hash with a zero byte. This is to
    decrease the collision rate between external chunk hashes and internal
    leaf hashes. Be aware this policy may be different from other tree
    specs.

    Because Write takes hash leaves rather than chunks of data, intermediate
    leaf levels may be verified.


FUNCTIONS

func New(digest hash.Hash) hash.Hash
    New returns a new hash.Hash that computes the root of a row of tree
    leaves. The digest argument is the hash.Hash that will be used to
    process the tree.


