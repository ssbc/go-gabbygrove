package gabbygrove

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/auth"
)

type Event struct {
	Previous  *BinaryRef // %... Metadata hashsha
	Author    *BinaryRef
	Sequence  uint64
	Timestamp uint64
	Content   Content
}

func (evt Event) MarshalCBOR() ([]byte, error) {
	var evtBuf bytes.Buffer
	enc := codec.NewEncoder(&evtBuf, GetCBORHandle())
	if err := enc.Encode(evt); err != nil {
		return nil, errors.Wrap(err, "gabbyGrove/Event: failed to encode to cbor")
	}
	return evtBuf.Bytes(), nil
}

func (evt *Event) UnmarshalCBOR(data []byte) error {
	evtDec := codec.NewDecoder(bytes.NewReader(data), GetCBORHandle())
	return errors.Wrapf(evtDec.Decode(evt), "gabbyGrove/Event: failed to decode")
}

type ContentType uint

const (
	ContentTypeUnknown ContentType = iota
	ContentTypeJSON
	ContentTypeCBOR
)

type Content struct {
	Type ContentType
	Size uint64
	Hash *BinaryRef
}

type Transfer struct {
	Event   []byte
	lazyEvt *Event

	Signature []byte
	Content   []byte
}

func (tr Transfer) MarshalCBOR() ([]byte, error) {
	var evtBuf bytes.Buffer
	enc := codec.NewEncoder(&evtBuf, GetCBORHandle())
	if err := enc.Encode(tr); err != nil {
		return nil, errors.Wrap(err, "failed to encode metadata")
	}
	return evtBuf.Bytes(), nil
}

func (tr *Transfer) UnmarshalCBOR(data []byte) error {
	evtDec := codec.NewDecoder(bytes.NewReader(data), GetCBORHandle())
	return evtDec.Decode(tr)
}

func (tr *Transfer) UnmarshaledEvent() (*Event, error) {
	return tr.getEvent()
}

func (tr *Transfer) getEvent() (*Event, error) {
	if tr.lazyEvt != nil {
		return tr.lazyEvt, nil
	}
	var evt Event
	err := evt.UnmarshalCBOR(tr.Event)
	if err != nil {
		return nil, err
	}
	tr.lazyEvt = &evt
	return &evt, nil
}

// Verify returns true if the Message was signed by the author specified by the meta portion of the message
func (tr *Transfer) Verify(hmacKey *[32]byte) bool {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	aref, err := evt.Author.GetRef(RefTypeFeed)
	if err != nil {
		panic(err)
	}

	pubKey := aref.(*ssb.FeedRef).ID

	toVerify := tr.Event
	if hmacKey != nil {
		mac := auth.Sum(tr.Event, hmacKey)
		toVerify = mac[:]
	}

	return ed25519.Verify(pubKey, toVerify, tr.Signature)
}

var _ ssb.Message = (*Transfer)(nil)

func (tr *Transfer) Seq() int64 {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	return int64(evt.Sequence)
}

func (tr *Transfer) Author() *ssb.FeedRef {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	aref, err := evt.Author.GetRef(RefTypeFeed)
	if err != nil {
		panic(err)
	}
	return aref.(*ssb.FeedRef)
}

func (tr *Transfer) Previous() *ssb.MessageRef {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	if evt.Previous == nil {
		return nil
	}
	mref, err := evt.Previous.GetRef(RefTypeMessage)
	if err != nil {
		panic(err)
	}
	return mref.(*ssb.MessageRef)
}

func (tr *Transfer) Timestamp() time.Time {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	return time.Unix(int64(evt.Timestamp), 0)
}

func (tr *Transfer) ContentBytes() []byte {
	return tr.Content
}

func (tr *Transfer) ValueContent() *ssb.Value {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	var msg ssb.Value
	if evt.Previous != nil {
		ref, err := evt.Previous.GetRef(RefTypeMessage)
		if err != nil {
			panic(err)
		}
		msg.Previous = ref.(*ssb.MessageRef)
	}
	aref, err := evt.Author.GetRef(RefTypeFeed)
	if err != nil {
		panic(err)
	}
	msg.Author = *aref.(*ssb.FeedRef)
	msg.Sequence = margaret.BaseSeq(evt.Sequence)
	msg.Hash = "sha256"
	// msg.Timestamp = float64(sm.Timestamp.Unix() * 1000)
	msg.Content = tr.Content
	return &msg
}

func (tr *Transfer) ValueContentJSON() json.RawMessage {
	jsonB, err := json.Marshal(tr.ValueContent())
	if err != nil {
		panic(err.Error())
	}

	return jsonB
}
