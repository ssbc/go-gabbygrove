package gabbygrove

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
	"go.cryptoscope.co/ssb"
)

var i = time.Date(2019, 07, 30, 0, 0, 0, 0, time.UTC).Unix()

func fakeNow() time.Time {
	t := time.Unix(i, 0)
	i++
	return t
}

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	now = fakeNow

	t.Log("kp:", kp.Id.Ref())

	var msgs = []interface{}{
		"foo.box",
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
		"83585785f6d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd011a5d3f8880830107d9041a582103e806ecf2b7c37fb06dc198a9b905be64ee3fdb8237ef80d316acb7c85bbf5f02584091f1b00c37285fc517d4c87fda951a6bc38aee7e7dcb8e3ce538289c5cba0e93a5734bd6853d11fa29ddf0bfe5bc4b5049ef4681caa1baa355cd2ffc9419110447666f6f2e626f78",
		"83587c85d9041a5821020113f4dd8c981d1d87bc7f46cf86e8e7b0fb774f839930dd38d6a13f69d9693dd9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd021a5d3f8881830116d9041a58210395cca4fa7b24abc6049683e716292b00c49509be147aa024c06286bd9b7dbda85840afe8658c6f5229951db4db82f62e9d930b6cd8f155c5d47586556012ed9c560487c05aae58a2b66970cbab666e43890deb01f33e5281b0f9c7e22f68a437af09567b2269223a312c2274797065223a2274657374227d0a",
		"83587d85d9041a582102f89a19b59a551b394679bef624816cf0b7a0edb3053de3153b18cbf100b41606d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd031a5d3f888283011869d9041a58210327d0b22f26328f03ffce2a7c66b2ee27e337ca5d28cdc89ead668f1dd7f0218b584046d73d9b193871c9c6624980a037232161b4189d2725b2beb7011fd29bd439aa3aee5418065df32a475fff82d230f2a884609ee9d6b91d203ca380fc12dce80c58697b22636f6e74616374223a224072745061746c7a70344e624644556238372f745649706274496262677454656d6f42684664633650584c303d2e6767666565642d7631222c2273706563746174696e67223a747275652c2274797065223a22636f6e74616374227d0a",
	}

	var prevRef *BinaryRef
	for msgidx, msg := range msgs {

		e := NewEncoder(kp)
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
			t.Log("want", wantHex[msgidx])
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
		a.EqualValues(0x5d3f8880+msgidx, evt.Timestamp)
		if msgidx == 0 {
			a.Nil(evt.Previous, "evt[%02d] has no previous", msgidx)
		} else {
			a.NotNil(evt.Previous, "evt[%02d] has previous", msgidx)
		}
		r.Equal(ContentTypeJSON, evt.Content.Type)
		a.NotEqual(0, evt.Content.Size)
	}
}

func TestEvtDecode(t *testing.T) {
	r := require.New(t)
	var input = "85d9041a5821026265656662656566626565666265656662656566626565666265656662656566d9041a582101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd031a5d3f888283011869d9041a58210327d0b22f26328f03ffce2a7c66b2ee27e337ca5d28cdc89ead668f1dd7f0218b"

	data, err := hex.DecodeString(input)
	r.NoError(err)
	r.NotNil(data)

	var evt Event
	evtDec := codec.NewDecoder(bytes.NewReader(data), GetCBORHandle())
	err = evtDec.Decode(&evt)
	r.NoError(err)
	r.NotNil(evt.Author)
	r.NotNil(evt.Previous)
	r.EqualValues("%YmVlZmJlZWZiZWVmYmVlZmJlZWZiZWVmYmVlZmJlZWY=.ggmsg-v1", evt.Previous.Ref())
	r.EqualValues("!J9CyLyYyjwP/zip8ZrLuJ+M3yl0ozcierWaPHdfwIYs=.gabby-v1-content", evt.Content.Hash.Ref())
	r.Equal(uint64(3), evt.Sequence)
	r.EqualValues(0x5d3f8882, evt.Timestamp)
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
