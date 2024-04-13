package rule

import (
	"net"
)

type ip16byte struct {
	next map[byte]*ip16byte
	mask *[7]map[byte]*ip16byte
	end  string
}

type IP struct {
	v4 *ip16byte
	v6 *ip16byte
}

func NewIp() IP {
	ir := IP{v6: &ip16byte{}}
	v6prefix := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	node := ir.v6
	for i := range v6prefix {
		node.next = make(map[byte]*ip16byte)
		tmp := &ip16byte{}
		node.next[v6prefix[i]] = tmp
		node = tmp
	}
	ir.v4 = node
	return ir
}

func (ir *IP) Append(cidr string, policy string) bool {
	_, ip, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	node := ir.v4
	if len(ip.IP) > 4 {
		node = ir.v6
	}
	for i, b := range ip.IP {
		if ip.Mask[i] == 0 {
			node.end = policy
			return true
		} else if ip.Mask[i] != 0xff {
			n, v := -1, ip.Mask[i]
			for v&0x80 != 0 {
				n++
				v <<= 1
			}
			if node.mask == nil {
				node.mask = &[7]map[byte]*ip16byte{}
			}
			if node.mask[n] == nil {
				node.mask[n] = make(map[byte]*ip16byte)
			}
			node.mask[n][b&ip.Mask[i]] = &ip16byte{end: policy}
			return true
		} else {
			if node.next == nil {
				node.next = make(map[byte]*ip16byte)
			}
			tmp, ok := node.next[b]
			if !ok {
				tmp = &ip16byte{}
				node.next[b] = tmp
			}
			node = tmp
		}
	}
	node.end = policy
	return true
}

var ipBitsMaskIdx = []byte{0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe}

func (ir *IP) Match(ip net.IP) string {
	node := ir.v4
	if len(ip) > 4 {
		node = ir.v6
	}
	for _, b := range ip {
		if len(node.end) > 0 {
			return node.end
		}
		if node.mask != nil {
			for i := range node.mask {
				if node.mask[i] != nil {
					if e, ok := node.mask[i][b&ipBitsMaskIdx[i]]; ok {
						return e.end
					}
				}
			}
		}
		node = node.next[b]
		if node == nil {
			return ""
		}
	}
	return node.end
}
