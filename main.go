package md5crypt

import (
	"crypto/md5"
)

const p64alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var permute [5][3]int

func init() {
	permute = [5][3]int{
		{0, 6, 12},
		{1, 7, 13},
		{2, 8, 14},
		{3, 9, 15},
		{4, 10, 5},
	}
}

func pass64(b []byte) []byte {
	pass := make([]byte, 0, (len(b)+1*4)/3)

	for _, v := range permute {

		v := int(b[v[0]])<<16 | int(b[v[1]])<<8 | int(b[v[2]])
		for j := 0; j < 4; j++ {
			pass = append(pass, p64alphabet[v&0x3f])
			v >>= 6
		}
	}
	v := b[11]
	pass = append(pass, p64alphabet[v&0x3f])
	v >>= 6
	pass = append(pass, p64alphabet[v&0x3f])

	return pass
}

func Hash(plain []byte, salt []byte) string {
	m := md5.New()
	m.Write(plain)
	m.Write(salt)
	m.Write(plain)
	final := m.Sum(nil)

	m.Reset()
	m.Write(plain)
	m.Write([]byte("$1$"))
	m.Write(salt)

	for i := len(plain); i > 0; i -= 16 {
		if i > 16 {
			m.Write(final[:16])
		} else {
			m.Write(final[:i])
		}
	}

	var ctx []byte
	for i := len(plain); i > 0; i >>= 1 {
		if i&1 == 1 {
			ctx = append(ctx, 0)
		} else {
			ctx = append(ctx, plain[0])
		}
	}

	m.Write(ctx)
	final = m.Sum(nil)

	for i := 0; i < 1000; i++ {
		m.Reset()

		if i&1 == 1 {
			m.Write(plain)
		} else {
			m.Write(final[:16])
		}

		if i%3 != 0 {
			m.Write(salt)
		}

		if i%7 != 0 {
			m.Write(plain)
		}

		if i&1 == 1 {
			m.Write(final[:16])
		} else {
			m.Write(plain)
		}

		final = m.Sum(nil)
	}
	return string(pass64(final))
}
