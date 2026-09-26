"""Bounded full-datagram support for Router VPN's exact pinned Xray checkout.

Only packet buffers grow. The ordinary 8 KiB stream pool remains unchanged.
The wire format still uses the original 16-bit length and XUDP framing.
"""
PATCHES = {
    'proxy/freedom/freedom.go': [
        ('func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {\n\tb := buf.New()\n\tb.Resize(0, buf.Size)',
         'func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {\n\tb := buf.NewWithSize(65535)\n\tb.Resize(0, 65535)'),
    ],
    'common/xudp/xudp.go': [
        ('if length == 0 || length+666 > buf.Size {\n\t\t\tcontinue\n\t\t}\n\n\t\teb := buf.New()',
         'if length == 0 {\n\t\t\tcontinue\n\t\t}\n\t\tif length > 65535 {\n\t\t\tbuf.ReleaseMulti(mb2Write)\n\t\t\treturn errors.New("XUDP payload exceeds its 16-bit datagram framing")\n\t\t}\n\n\t\teb := buf.NewWithSize(length + 666)'),
        ('if l < 4 {', 'if l < 4 || l > buf.Size {'),
        ('\t\t\tif length > 0 {\n\t\t\t\tif _, err := b.ReadFullFrom(r.Reader, length); err != nil {',
         '\t\t\tif length > 0 {\n\t\t\t\tif length > buf.Size {\n\t\t\t\t\taddress := b.UDP\n\t\t\t\t\tb.Release()\n\t\t\t\t\tb = buf.NewWithSize(length)\n\t\t\t\t\tb.UDP = address\n\t\t\t\t}\n\t\t\t\tif _, err := b.ReadFullFrom(r.Reader, length); err != nil {'),
    ],
    'common/mux/reader.go': [
        ('\n\t"github.com/xtls/xray-core/common/errors"', ''),
        ('\tif size > buf.Size {\n\t\treturn nil, errors.New("packet size too large: ", size)\n\t}\n\n\tb := buf.New()',
         '\tb := buf.New()\n\tif size > buf.Size {\n\t\tb.Release()\n\t\tb = buf.NewWithSize(int32(size))\n\t}'),
    ],
    'common/buf/reader.go': [
        ('func readOneUDP(r io.Reader) (*Buffer, error) {\n\tb := New()',
         'func readOneUDP(r io.Reader) (*Buffer, error) {\n\tb := NewWithSize(65535)'),
    ],
}

def patch_text(path, text):
    pairs=PATCHES[path]
    # A fully applied patch is idempotent; partial edits are rejected, not mixed.
    applied=all(new in text if new else old not in text for old,new in pairs)
    if applied:
        for old,new in pairs:
            if new and text.count(new)!=1: raise ValueError('Duplicate native datagram boundary: '+path)
        return text
    for old,new in pairs:
        if text.count(old)!=1: raise ValueError('Pinned native datagram boundary changed: '+path)
        text=text.replace(old,new,1)
    return text

def prepare(root):
    changes={root/path:patch_text(path,(root/path).read_text()) for path in PATCHES}
    for path,text in changes.items(): path.write_text(text)
