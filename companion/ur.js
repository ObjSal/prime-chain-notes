// Minimal UR (bc-ur / BCR-2020-005) *encoder* — just enough to emit the
// pure sequential parts `ur:bytes/N-M/<bytewords>` that the KeyOS system
// QR scanner (foundation-ur) reassembles. Byte-exact against the
// foundation-ur reference encoder; verified by
// tests/test_companion_qr.py against notes-core's ur_encode/ur_decode
// examples. Works in the browser (window.CNUR) and under node (exports).
"use strict";

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.CNUR = factory();
})(typeof self !== "undefined" ? self : this, function () {
  // foundation-ur bytewords MINIMALS table (2-letter forms), index = byte.
  const MINIMALS = (
    "ae ad ao ax aa ah am at ay as bk bd bn bt ba bs be by bg bw bb bz cm ch cs cf cy cw ce ca ck ct " +
    "cx cl cp cn dk da ds di de dt dr dn dw dp dm dl dy eh ey eo ee ec en em et es ft fr fn fs fm fh " +
    "fz fp fw fx fy fe fg fl fd ga ge gr gs gt gl gw gd gy gm gu gh go hf hg hd hk ht hp hh hl hy he " +
    "hn hs id ia ie ih iy io is in im je jz jn jt jl jo js jp jk jy kp ko kt ks kk kn kg ke ki kb lb " +
    "la ly lf ls lr lp ln lt lo ld le lu lk lg mn my mh me mo mu mw md mt ms mk nl ny nd ns nt nn ne " +
    "nb oy oe ot ox on ol os pd pt pk py ps pm pl pe pf pa pr qd qz re rp rl ro rh rd rk rf ry rn rs " +
    "rt se sa sr ss sk sw st sp so sg sb sf sn to tk ti tt td te ty tl tb ts tp ta tn uy uo ut ue ur " +
    "vt vy vo vl ve vw va vd vs wl wd wm wp we wy ws wt wn wz wf wk yk yn yl ya yt zs zo zt zc ze zm"
  ).split(" ");

  // Standard CRC32 (poly 0xEDB88320), as used by bc-ur.
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  // CBOR helpers (only what a fountain part needs).
  function cborUint(n, out) {
    if (n < 24) out.push(n);
    else if (n < 0x100) out.push(0x18, n);
    else if (n < 0x10000) out.push(0x19, n >>> 8, n & 0xff);
    else out.push(0x1a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
  function cborBytesHeader(len, out) {
    if (len < 24) out.push(0x40 + len);
    else if (len < 0x100) out.push(0x58, len);
    else if (len < 0x10000) out.push(0x59, len >>> 8, len & 0xff);
    else out.push(0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
  }

  // bytewords minimal: data ++ crc32(data), two letters per byte.
  function bytewordsMinimal(bytes) {
    const crc = crc32(bytes);
    const all = new Uint8Array(bytes.length + 4);
    all.set(bytes);
    all[bytes.length] = (crc >>> 24) & 0xff;
    all[bytes.length + 1] = (crc >>> 16) & 0xff;
    all[bytes.length + 2] = (crc >>> 8) & 0xff;
    all[bytes.length + 3] = crc & 0xff;
    let s = "";
    for (let i = 0; i < all.length; i++) s += MINIMALS[all[i]];
    return s;
  }

  // Pure sequential fountain parts (1..seqLen) for `message` — enough for
  // the decoder to complete without mixed parts.
  function encodeParts(message, maxFragmentLen) {
    const seqLen = Math.max(1, Math.ceil(message.length / maxFragmentLen));
    const fragLen = Math.ceil(message.length / seqLen);
    const checksum = crc32(message);
    const parts = [];
    for (let seq = 1; seq <= seqLen; seq++) {
      const frag = new Uint8Array(fragLen); // zero-padded final fragment
      frag.set(message.slice((seq - 1) * fragLen, seq * fragLen));
      const cbor = [0x85];
      cborUint(seq, cbor);
      cborUint(seqLen, cbor);
      cborUint(message.length, cbor);
      cborUint(checksum, cbor);
      cborBytesHeader(frag.length, cbor);
      const cborBytes = new Uint8Array(cbor.length + frag.length);
      cborBytes.set(cbor);
      cborBytes.set(frag, cbor.length);
      parts.push(`ur:bytes/${seq}-${seqLen}/${bytewordsMinimal(cborBytes)}`);
    }
    return parts;
  }

  return { encodeParts, crc32, bytewordsMinimal };
});
