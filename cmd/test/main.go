package main

import "fmt"

// 00000000  08 00 00 00 01 00 08 00  00 00 01 11 08 00 45 00  |..............E.|
// 00000010  00 96 02 3c 40 00 40 11  20 18 0a 00 01 01 0a 00  |...<@.@. .......|
// 00000020  03 03 d9 6a 11 5c 00 82  5b ed 16 fe fd 00 00 00  |...j.\..[.......|
// 00000030  00 00 00 00 00 00 6d 01  00 00 61 00 00 00 00 00  |......m...a.....|
// 00000040  00 00 61 fe fd 65 ae 27  ea 6a 9b 0a 13 49 92 8e  |..a..e.'.j...I..|
// 00000050  80 8d 21 69 ab 65 24 8c  38 08 47 30 29 8c 7f 68  |..!i.e$.8.G0)..h|
// 00000060  58 2f 04 fb 3c 00 00 00  0c c0 2b c0 2f c0 0a c0  |X/..<.....+./...|
// 00000070  14 c0 2c c0 30 01 00 00  2b 00 0d 00 10 00 0e 04  |..,.0...+.......|
// 00000080  03 05 03 06 03 04 01 05  01 06 01 08 07 ff 01 00  |................|
// 00000090  01 00 00 0a 00 08 00 06  00 1d 00 17 00 18 00 0b  |................|
// 000000a0  00 02 01 00

func getPayload() []byte {
	return []byte{
		0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x11, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x96, 0x02, 0x3c, 0x40, 0x00, 0x40, 0x11, 0x20, 0x18, 0x0a, 0x00, 0x01, 0x01, 0x0a, 0x00,
		0x03, 0x03, 0xd9, 0x6a, 0x11, 0x5c, 0x00, 0x82, 0x5b, 0xed, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x01, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x61, 0xfe, 0xfd, 0x65, 0xae, 0x27, 0xea, 0x6a, 0x9b, 0x0a, 0x13, 0x49, 0x92, 0x8e,
	}
}

type CipherSuite interface {
	modify(int)
	display()
}

type Foo struct {
	num int
}

func (f *Foo) modify(x int) {
	f.num = x
}

func (f *Foo) display() {
	fmt.Println(f.num)
}

func main() {
	foo := Foo{}
	foo.modify(1)
	foo.display()

	var cs CipherSuite
	cs = &foo
	cs.modify(2)
	cs.display()

	cs2 := cs
	cs2.modify(5)
	cs2.display()
}
