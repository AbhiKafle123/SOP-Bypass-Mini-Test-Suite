/**
 * Minimal PNG encoder — enough to emit an 8-bit greyscale image whose pixel
 * values are chosen bytes.
 *
 * Why this exists: testing canvas origin-tainting properly needs a cross-origin
 * image whose contents are *recoverable and verifiable*. If the image is just a
 * coloured square, a probe that manages to read its pixels back can only report
 * "I read some pixels", which is indistinguishable from reading a blank canvas
 * it created itself. Encoding the per-run canary into the pixel values means a
 * successful read reconstructs the exact secret string, and the runner's existing
 * canary check grades it with no special-casing.
 *
 * No dependencies: zlib is in core and CRC-32 is twelve lines.
 */
'use strict';

const zlib = require('zlib');

let CRC_TABLE = null;
function crcTable() {
  if (CRC_TABLE) return CRC_TABLE;
  CRC_TABLE = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    CRC_TABLE[n] = c;
  }
  return CRC_TABLE;
}

function crc32(buf) {
  const t = crcTable();
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

/**
 * Encode `text` as a 1-pixel-tall, 8-bit greyscale PNG, one pixel per byte.
 *
 * Greyscale is deliberate: with colour type 0 there is no palette or alpha to
 * complicate readback, and a reader recovers byte N as the red channel of pixel
 * N in the canvas ImageData. Width is padded so the image is never zero-width.
 */
function encodeTextAsGreyscalePng(text) {
  const bytes = Buffer.from(String(text), 'latin1');
  const width = Math.max(1, bytes.length);
  const height = 1;

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 0;   // colour type 0 = greyscale
  ihdr[10] = 0;  // deflate
  ihdr[11] = 0;  // adaptive filtering
  ihdr[12] = 0;  // no interlace

  // One scanline, prefixed with filter-type byte 0 (None) as the format requires.
  const raw = Buffer.concat([Buffer.from([0]), bytes]);
  const idat = zlib.deflateSync(raw, { level: 9 });

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

module.exports = { encodeTextAsGreyscalePng, crc32 };
