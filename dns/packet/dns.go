package packet

import (
	"encoding/binary"
	"net"
)

const (
	OpCodeQuery         uint8  = 0
	RCodeFormatError    uint8  = 1
	RCodeServerFailure  uint8  = 2
	RCodeNotImplemented uint8  = 4
	DNSTypeA            uint16 = 1
	DNSTypeAAAA         uint16 = 28
	DNSClassIN          uint16 = 1
)

type DNS struct {
	Addr   net.Addr
	Data   []byte
	ID     uint16
	OpCode uint8
	Type   uint16
	Quest  string
}

func (d *DNS) DecodeReq() uint8 {
	if len(d.Data) < 12 {
		return RCodeFormatError
	}
	d.ID = binary.BigEndian.Uint16(d.Data[:2])
	if d.Data[2]&0x80 != 0 {
		return RCodeFormatError
	}
	d.OpCode = (d.Data[2] >> 3) & 0x0F
	if d.OpCode != OpCodeQuery {
		return 0
	}
	count := binary.BigEndian.Uint16(d.Data[4:6])
	if count == 0 {
		return RCodeFormatError
	}
	offset := 12
	for d.Data[offset] != 0 {
		offset++
	}
	offset++
	d.Type = binary.BigEndian.Uint16(d.Data[offset : offset+2])
	cls := binary.BigEndian.Uint16(d.Data[offset+2 : offset+4])
	d.Quest = ""
	if (d.Type == DNSTypeA || d.Type == DNSTypeAAAA) && cls == DNSClassIN {
		if name := d.Data[12 : offset-1]; len(name) > 3 {
			buf := make([]byte, len(name)-1)
			copy(buf, name[1:])
			idx := int(name[0] + 1)
			for idx < len(name) {
				buf[idx-1] = '.'
				idx += int(name[idx] + 1)
			}
			d.Quest = string(buf)
		}
	}
	if count > 1 {
		binary.BigEndian.PutUint16(d.Data[4:], 1)
		binary.BigEndian.PutUint16(d.Data[6:], 0)
		binary.BigEndian.PutUint16(d.Data[8:], 0)
		binary.BigEndian.PutUint16(d.Data[10:], 0)
		d.Data = d.Data[:offset+4]
	}
	return 0
}

func (d *DNS) DecodeResp() (int, bool) {
	if len(d.Data) < 12 {
		return 0, false
	}
	d.ID = binary.BigEndian.Uint16(d.Data[:2])
	if d.Data[2]&0x80 == 0 {
		return 0, false
	}
	if d.Data[3]&0xF != 0 {
		return 0, false
	}
	d.OpCode = (d.Data[2] >> 3) & 0x0F
	return int(binary.BigEndian.Uint16(d.Data[6:8])), true
}

func (d *DNS) DecodeAnswer() []net.IP {
	qd := binary.BigEndian.Uint16(d.Data[4:6])
	an := binary.BigEndian.Uint16(d.Data[6:8])
	ip := make([]net.IP, 0, an)
	offset := 12
	for i := 0; i < int(qd); i++ {
		for d.Data[offset] != 0x00 {
			if d.Data[offset]&0xC0 == 0xC0 {
				offset++
				break
			}
			offset++
		}
		offset += 5
	}
	for i := 0; i < int(an); i++ {
		for d.Data[offset] != 0x00 {
			if d.Data[offset]&0xC0 == 0xC0 {
				offset++
				break
			}
			offset++
		}
		offset++
		tp := binary.BigEndian.Uint16(d.Data[offset : offset+2])
		if tp == DNSTypeA {
			tmp := make([]byte, 4)
			copy(tmp, d.Data[offset+10:])
			ip = append(ip, tmp)
		} else if tp == DNSTypeAAAA {
			tmp := make([]byte, 16)
			copy(tmp, d.Data[offset+10:])
			ip = append(ip, tmp)
		}
		offset += 10 + int(binary.BigEndian.Uint16(d.Data[offset+8:offset+10]))
	}
	return ip
}

func (d *DNS) EncodeResp(name string, ip net.IP) {
	d.Data = d.Data[:cap(d.Data)]
	binary.BigEndian.PutUint16(d.Data, d.ID)
	d.Data[2] = (1 << 7) | (d.OpCode << 3) | 1 // qr rd
	d.Data[3] = 1 << 7                         // ra
	binary.BigEndian.PutUint16(d.Data[4:], 1)
	binary.BigEndian.PutUint16(d.Data[6:], 1)
	binary.BigEndian.PutUint16(d.Data[8:], 0)
	binary.BigEndian.PutUint16(d.Data[10:], 0)
	offset := 12
	n := 0
	for j := range name {
		if name[j] == '.' {
			d.Data[offset+j-n] = byte(n)
			n = 0
		} else {
			d.Data[offset+j+1] = name[j]
			n++
		}
	}
	d.Data[offset+len(name)-n] = byte(n)
	d.Data[offset+len(name)+1] = 0x00
	offset += len(name) + 2
	binary.BigEndian.PutUint16(d.Data[offset:], d.Type)
	binary.BigEndian.PutUint16(d.Data[offset+2:], DNSClassIN)
	offset += 4
	d.Data[offset] = 0xC0
	d.Data[offset+1] = 0x0C
	offset += 2
	if d.Type == DNSTypeAAAA {
		ip = ip.To16()
	}
	binary.BigEndian.PutUint16(d.Data[offset:], d.Type)
	binary.BigEndian.PutUint16(d.Data[offset+2:], DNSClassIN)
	binary.BigEndian.PutUint32(d.Data[offset+4:], uint32(300))     // TTL
	binary.BigEndian.PutUint16(d.Data[offset+8:], uint16(len(ip))) // DataLength
	copy(d.Data[offset+10:], ip)
	offset += 10 + len(ip)
	d.Data = d.Data[:offset]
}

func (d *DNS) EncodeErrResp(code uint8) {
	d.Data = d.Data[:12]
	binary.BigEndian.PutUint16(d.Data, d.ID)
	d.Data[2] = (1 << 7) | (d.OpCode << 3) | 1 // qr rd
	d.Data[3] = (1 << 7) | code                // ra
	binary.BigEndian.PutUint16(d.Data[4:], 0)
	binary.BigEndian.PutUint16(d.Data[6:], 0)
	binary.BigEndian.PutUint16(d.Data[8:], 0)
	binary.BigEndian.PutUint16(d.Data[10:], 0)
}

func SetDnsId(data []byte, id uint16) { binary.BigEndian.PutUint16(data, id) }
