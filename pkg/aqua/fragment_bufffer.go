package aqua

import "github.com/yly97/dtlshps/pkg/layer"

type fragment struct {
	header                layer.HandshakeHeader // 分片合并完后需要重新计算
	payload               []byte                // 握手消息负载
	currentFragmentLength int                   // 当前分片长度
}

func newFragment(header layer.HandshakeHeader) *fragment {
	return &fragment{
		header:  header,
		payload: make([]byte, header.MessageLength),
	}
}

// populate 填充分片
func (f *fragment) populate(offset int, data []byte) (bool, error) {
	if f.currentFragmentLength+len(data) > len(f.payload) {
		return false, errFragmentLengthMismatch
	}

	copy(f.payload[offset:offset+len(data)], data)
	f.currentFragmentLength += len(data)

	if len(f.payload) == f.currentFragmentLength {
		return true, nil
	}
	return false, nil
}

type fragmentBuffer struct {
	buffer map[uint16]*fragment
}

func newFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{
		buffer: make(map[uint16]*fragment),
	}
}

// merge 合并分片，如果传入的是完整的消息或是该消息的最后一块分片则返回数据，
// 否则缓存该分片并返回nil
func (b *fragmentBuffer) merge(data []byte) ([]byte, error) {
	h := layer.HandshakeHeader{}
	if err := h.Unmarshal(data); err != nil {
		return nil, err
	}

	// 如果消息未分片，不缓存
	if h.MessageLength == h.FragmentLength {
		return data, nil
	}

	seq := h.MessageSequence
	if _, ok := b.buffer[seq]; !ok {
		b.buffer[seq] = newFragment(h)
	}
	frag := b.buffer[seq]
	isComplete, err := frag.populate(int(h.FragmentOffset), data[layer.HandshakeHeaderSize:])
	if err != nil {
		return nil, err
	}
	if isComplete {
		// 该消息序列号的分片全部接收到
		frag.header.FragmentOffset = 0
		frag.header.FragmentLength = frag.header.MessageLength
		out, err := frag.header.Marshal()
		if err != nil {
			return nil, err
		}
		delete(b.buffer, seq)
		return append(out, frag.payload...), nil
	}

	// 该消息序列号的分片未处理完
	return nil, nil
}
