package gabbygrove

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
	"go.cryptoscope.co/ssb"
)

var startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()

func fakeNow() time.Time {
	t := time.Unix(startTime, 0)
	startTime++
	return t
}

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()
	now = fakeNow

	t.Log("kp:", kp.Id.Ref())

	var msgs = []interface{}{
		[]byte("\"some json string!\""),
		map[string]interface{}{
			"type": "test",
			"i":    1,
		},
		map[string]interface{}{
			"type":       "contact",
			"contact":    kp.Id.Ref(),
			"spectating": true,
		},
	}

	wantHex := []string{
		"83585385f6d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd012483d9041a5821034793ac902a118e3403229a3229fcf0e002b5d9c919e66aa70ab69724f11e189213005840e2929c3231a39b72a5a8024d773c26a72451be6f370a675e156cb0607f1155aeb94e952939aedb9304e5b06881b75e53bce907d20f6806203b33412d9cd73f035322736f6d65206a736f6e20737472696e672122",
		"83587885d9041a582102fd23be5e971553b094656fae4004e1e48615058c6e11a2e2a0baea0fb4770f09d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd022383d9041a58210395cca4fa7b24abc6049683e716292b00c49509be147aa024c06286bd9b7dbda816015840a9314593ea6ca8205bc3d152395e06210c349a1a599a4712096be232f0531efb3ce856a462265d2ffb5ae9f8050c4f04a08f76ee3db3842f7a75c29a74cc000b567b2269223a312c2274797065223a2274657374227d0a",
		"83587985d9041a58210245e67672a01d920e7513c447320cc9f01027531103eb7cbf8e30e6f1513f0edcd9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd032283d9041a58210327d0b22f26328f03ffce2a7c66b2ee27e337ca5d28cdc89ead668f1dd7f0218b186901584083ddf063762e0296bdbbc1c4d1bb051f9db2c930db79cf641c48d8c2eff39dbd35b8cfa187a035b482466048808f834d245011e74ff76252b1cce84abc41990f58697b22636f6e74616374223a224072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6767666565642d7631222c2273706563746174696e67223a747275652c2274797065223a22636f6e74616374227d0a",
	}

	var prevRef *BinaryRef
	for msgidx, msg := range msgs {

		e := NewEncoder(kp)
		e.WithNowTimestamps(true)
		seq := uint64(msgidx + 1)
		tr, msgRef, err := e.Encode(seq, prevRef, msg)
		r.NoError(err, "msg[%02d]Encode failed", msgidx)
		r.NotNil(msgRef)

		got, err := tr.MarshalCBOR()
		r.NoError(err, "msg[%02d]Marshal failed", msgidx)

		want, err := hex.DecodeString(wantHex[msgidx])
		r.NoError(err)

		a.Equal(len(want), len(got), "msg[%02d] wrong msg length", msgidx)
		if !a.Equal(want, got, "msg[%02d] compare failed", msgidx) {
			t.Log("got", hex.EncodeToString(got))
		}

		r.True(tr.Verify(nil), "msg[%02d] did not verify", msgidx)

		prevRef, err = fromRef(tr.Key())
		r.NoError(err)

		var tr2 Transfer
		err = tr2.UnmarshalCBOR(got)
		r.NoError(err, "msg[%02d] test decode failed", msgidx)
		t.Logf("msg[%02d] transfer decode of %d bytes", msgidx, len(got))
		r.NotNil(tr2.Event)
		r.NotNil(tr2.Signature)
		r.NotNil(tr2.Content)

		t.Log("event bytes:", len(tr2.Event))
		t.Log(hex.EncodeToString(tr2.Event))

		var evt Event
		err = evt.UnmarshalCBOR(tr2.Event)
		r.NoError(err, "evt[%02d] unmarshal failed", msgidx)

		a.NotNil(evt.Author, "evt[%02d] has author", msgidx)
		a.Equal(seq, evt.Sequence)

		r.NotEqual(0, evt.Timestamp)
		a.EqualValues(-5+msgidx, evt.Timestamp)
		if msgidx == 0 {
			a.Nil(evt.Previous, "evt[%02d] has no previous", msgidx)
			a.Equal(ContentTypeArbitrary, evt.Content.Type)
		} else {
			a.NotNil(evt.Previous, "evt[%02d] has previous", msgidx)
			a.Equal(ContentTypeJSON, evt.Content.Type)
		}

		a.NotEqual(0, evt.Content.Size)
	}
}

func TestEvtDecode(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)

	var input = "85d9041a5821024226e0304155aeea683a98882ca5683579e1cdd5505597fb76498bf4c4973b98d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd032283d9041a58210327d0b22f26328f03ffce2a7c66b2ee27e337ca5d28cdc89ead668f1dd7f0218b186901"

	data, err := hex.DecodeString(input)
	r.NoError(err)
	r.NotNil(data)

	var evt Event
	evtDec := codec.NewDecoder(bytes.NewReader(data), GetCBORHandle())
	err = evtDec.Decode(&evt)
	r.NoError(err, "decode failed")
	a.NotNil(evt.Author)
	a.NotNil(evt.Previous)
	a.EqualValues("%QibgMEFVrupoOpiILKVoNXnhzdVQVZf7dkmL9MSXO5g=.ggmsg-v1", evt.Previous.Ref())
	a.EqualValues("!J9CyLyYyjwP/zip8ZrLuJ+M3yl0ozcierWaPHdfwIYs=.gabby-v1-content", evt.Content.Hash.Ref())
	a.Equal(uint64(3), evt.Sequence)
	a.EqualValues(-3, evt.Timestamp)
}
func TestEncodeLargestMsg(t *testing.T) {
	r := require.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	startTime = time.Date(1969, 12, 31, 23, 59, 55, 0, time.UTC).Unix()
	now = fakeNow

	largeMsg := bytes.Repeat([]byte("X"), math.MaxUint16)

	e := NewEncoder(kp)
	seq := uint64(9999999)
	fakeRef, err := fromRef(&ssb.MessageRef{
		Algo: ssb.RefAlgoMessageGabby,
		Hash: bytes.Repeat([]byte("b4ut"), 8),
	})
	r.NoError(err)
	tr, _, err := e.Encode(seq, fakeRef, largeMsg)
	r.NoError(err, "Encode worked!!")
	r.NotNil(tr)
	trcbor, err := tr.MarshalCBOR()
	r.NoError(err)

	t.Log("len evt:", len(tr.Event))
	t.Log("len total-content:", len(trcbor)-math.MaxUint16)

	ioutil.WriteFile(t.Name(), trcbor, 0700)
	var gotTr Transfer
	err = gotTr.UnmarshalCBOR(trcbor)
	r.NoError(err)

}

func TestEncodeTooLarge(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	tooLargeMsg := bytes.Repeat([]byte("A"), math.MaxUint16+10)

	e := NewEncoder(kp)
	seq := uint64(1)
	tr, msgRef, err := e.Encode(seq, nil, tooLargeMsg)
	r.Error(err, "Encode worked!!")
	if !a.Nil(tr) {
		trcbor, err := tr.MarshalCBOR()
		r.NoError(err)
		ioutil.WriteFile(t.Name(), trcbor, 0700)
	}
	r.Nil(msgRef)
}

func TestDecodeContentTooLarge(t *testing.T) {
	r := require.New(t)
	// disable the error check in TestEncodeTooLarge to get this data
	var input = "83585385f6d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd0124830009d9041a582103e083c9bbcf9d9a5e096f3282216242afe6ec263b6b03b88b7aa509a1ef59d3b25840763688ad9221a30cf05ef71d1e7daa2824741fa0981c67114f1cb0c6cbd63edee8f022fd52a2104eeee0d690995a44c362f971fe34c0531689ae8ae6d75a0f0a5a00010009"
	input += string(bytes.Repeat([]byte("41"), math.MaxUint16+10))

	data, err := hex.DecodeString(input)
	r.NoError(err)
	r.NotNil(data)

	var tr Transfer
	err = tr.UnmarshalCBOR(data)
	r.Error(err, "unmarshal of too large object worked")

}

func benchmarkEncoder(i int, b *testing.B) {
	r := require.New(b)

	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	e := NewEncoder(kp)

	fakeRef, _ := fromRef(&ssb.MessageRef{
		Hash: []byte("herberd"),
		Algo: ssb.RefAlgoMessageGabby,
	})

	msg := map[string]interface{}{
		"type":       "contact",
		"contact":    kp.Id.Ref(),
		"spectating": true,
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {

		for k := i; k > 0; k-- {
			tr, msgRef, err := e.Encode(uint64(k+1), fakeRef, msg)
			r.NoError(err, "msg[%02d]Encode failed")
			r.NotNil(tr)
			r.NotNil(msgRef)
			// r.True(tr.Verify())
		}
	}
}

func BenchmarkEncoder5(b *testing.B)   { benchmarkEncoder(5, b) }
func BenchmarkEncoder500(b *testing.B) { benchmarkEncoder(500, b) }
func BenchmarkEncoder20k(b *testing.B) { benchmarkEncoder(20000, b) }

func benchmarkVerify(i int, b *testing.B) {
	r := require.New(b)

	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	e := NewEncoder(kp)

	fakeRef, _ := fromRef(&ssb.MessageRef{
		Hash: bytes.Repeat([]byte("herb"), 8),
		Algo: ssb.RefAlgoMessageGabby,
	})

	msg := true
	var trs []Transfer
	for k := i; k > 0; k-- {
		tr, msgRef, err := e.Encode(uint64(k+1), fakeRef, msg)
		r.NoError(err, "msg[%02d]Encode failed")
		r.NotNil(tr)
		r.NotNil(msgRef)
		r.True(tr.Verify(nil))
		trs = append(trs, *tr)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, tr := range trs {
			r.True(tr.Verify(nil))
		}
	}
}

func BenchmarkVerify5(b *testing.B)   { benchmarkVerify(5, b) }
func BenchmarkVerify500(b *testing.B) { benchmarkVerify(500, b) }
func BenchmarkVerify20k(b *testing.B) { benchmarkVerify(20000, b) }
