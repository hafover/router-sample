package rule

import (
	"strings"
)

type domainKey struct {
	next  map[string]*domainKey
	other *domainKey
	ek    string // end key
	es    string // end star key
	ep    string // end plus key
}

type domainNode struct {
	prev *domainNode
	next *domainNode
	key  *domainKey
	flag int
}

func newDomainNode() *domainNode {
	node := &domainNode{}
	node.prev, node.next = node, node
	return node
}

func (*domainNode) insert(pos *domainNode, k *domainKey) {
	n := &domainNode{prev: pos.prev, next: pos, key: k}
	pos.prev.next = n
	pos.prev = n
}

func (*domainNode) remove(n *domainNode) {
	n.next.prev = n.prev
	n.prev.next = n.next
}

type Domain struct {
	root *domainKey
}

func NewDomain() Domain {
	return Domain{root: &domainKey{}}
}

func (dr *Domain) Append(name string, policy string) bool {
	sect := strings.Split(name, ".")
	if len(sect) < 2 {
		return false
	}
	key := dr.root
	for i := len(sect) - 1; i >= 0; i-- {
		if len(sect[i]) == 0 {
			return false
		}
		if sect[i] == "*" {
			if i == 0 {
				key.es = policy
				return true
			}
			if key.other == nil {
				key.other = &domainKey{}
			}
			key = key.other
		} else if sect[i] == "+" {
			if i != 0 {
				return false
			}
			key.ek, key.ep = policy, policy
			return true
		} else {
			if key.next == nil {
				key.next = make(map[string]*domainKey)
			}
			if tmp, ok := key.next[sect[i]]; ok {
				key = tmp
			} else {
				tmp = &domainKey{}
				key.next[sect[i]] = tmp
				key = tmp
			}
		}
	}
	key.ek = policy
	return true
}

func (dr *Domain) Match(name string) string {
	sect := strings.Split(name, ".")
	if len(sect) < 2 {
		return ""
	}
	list := newDomainNode()
	list.insert(list, dr.root)
	for i := len(sect) - 1; i >= 0; i-- {
		for n := list.next; n != list; n = n.next {
			if n.flag > 0 {
				continue
			}
			if k, ok := n.key.next[sect[i]]; ok {
				list.insert(n, k)
			}
			if n.key.other != nil {
				list.insert(list, n.key.other)
			}
			if i == 0 && len(n.key.es) > 0 {
				n.flag |= 2
			}
			if len(n.key.ep) > 0 {
				n.flag |= 4
			}
			if n.flag == 0 {
				list.remove(n)
			}
		}
	}
	for n := list.next; n != list; n = n.next {
		if n.flag == 0 && len(n.key.ek) > 0 {
			return n.key.ek
		}
		if n.flag&2 > 0 {
			return n.key.es
		}
		if n.flag&4 > 0 {
			return n.key.ep
		}
	}
	return ""
}
