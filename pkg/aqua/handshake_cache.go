// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package aqua

import (
	"github.com/yly97/dtlshps/pkg/layer"
)

type handshakeCacheItem struct {
	typ             layer.MessageType
	isClient        bool
	messageSequence uint16
	data            []byte
}

type handshakeCachePullRule struct {
	typ      layer.MessageType
	isClient bool
	optional bool
}

type handshakeCache struct {
	cache []*handshakeCacheItem
}

func newHandshakeCache() *handshakeCache {
	return &handshakeCache{}
}

func (h *handshakeCache) push(data []byte, messageSequence uint16, typ layer.MessageType, isClient bool) {
	h.cache = append(h.cache, &handshakeCacheItem{
		data:            append([]byte{}, data...),
		messageSequence: messageSequence,
		typ:             typ,
		isClient:        isClient,
	})
}

// returns a list handshakes that match the requested rules
// the list will contain null entries for rules that can't be satisfied
// multiple entries may match a rule, but only the last match is returned (ie ClientHello with cookies)
func (h *handshakeCache) pull(rules ...handshakeCachePullRule) []*handshakeCacheItem {
	out := make([]*handshakeCacheItem, len(rules))
	for i, r := range rules {
		for _, c := range h.cache {
			if c.typ == r.typ && c.isClient == r.isClient {
				switch {
				case out[i] == nil:
					out[i] = c
				case out[i].messageSequence < c.messageSequence:
					out[i] = c
				}
			}
		}
	}

	return out
}

// fullPullMap pulls all handshakes between rules[0] to rules[len(rules)-1] as map.
func (h *handshakeCache) fullPullMap(startSeq int, rules ...handshakeCachePullRule) (int, map[layer.MessageType]layer.Message, bool) {
	ci := make(map[layer.MessageType]*handshakeCacheItem)
	for _, r := range rules {
		var item *handshakeCacheItem
		for _, c := range h.cache {
			if c.typ == r.typ && c.isClient == r.isClient {
				switch {
				case item == nil:
					item = c
				case item.messageSequence < c.messageSequence:
					item = c
				}
			}
		}
		if !r.optional && item == nil {
			// Missing mandatory message.
			return startSeq, nil, false
		}
		ci[r.typ] = item
	}
	out := make(map[layer.MessageType]layer.Message)
	seq, ok := startSeq, false
	for _, r := range rules {
		typ := r.typ
		item := ci[typ]
		if item == nil {
			continue
		}
		rawHandshake := &layer.Handshake{}
		if err := rawHandshake.Unmarshal(item.data); err != nil {
			return startSeq, nil, false
		}
		if uint16(seq) != rawHandshake.Header.MessageSequence {
			// There is a gap. Some messages are not arrived.
			return startSeq, nil, false
		}
		ok = true
		seq++
		out[typ] = rawHandshake.Message
	}
	return seq, out, ok
}

// pullAndMerge calls pull and then merges the results, ignoring any null entries
func (h *handshakeCache) pullAndMerge(rules ...handshakeCachePullRule) []byte {
	merged := []byte{}

	for _, p := range h.pull(rules...) {
		if p != nil {
			merged = append(merged, p.data...)
		}
	}
	return merged
}
