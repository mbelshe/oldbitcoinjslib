Bitcoin.ECKey = (function () {
  var ECDSA = Bitcoin.ECDSA;
  var ecparams = getSECCurveByName("secp256k1");
  var rng = new SecureRandom();

  var ECKey = function (input) {
    if (!input) {
      // Generate new key
      var n = ecparams.getN();
      this.priv = ECDSA.getBigRandom(n);
    } else if (input instanceof BigInteger) {
      // Input is a private key value
      this.priv = input;
    } else if (Bitcoin.Util.isArray(input)) {
      // Prepend zero byte to prevent interpretation as negative integer
      this.priv = BigInteger.fromByteArrayUnsigned(input);
    } else if ("string" == typeof input) {
      if (input.length == 51) {
        // Base58 encoded private key
        this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input));
      } else {
        // Prepend zero byte to prevent interpretation as negative integer
        this.priv = BigInteger.fromByteArrayUnsigned(Crypto.util.base64ToBytes(input));
      }
    }
    this.compressed = !!ECKey.compressByDefault;
  };

  /**
   * Whether public keys should be returned compressed by default.
   */
  ECKey.compressByDefault = false;

  /**
   * Set whether the public key should be returned compressed or not.
   */
  ECKey.prototype.setCompressed = function (v) {
    this.compressed = !!v;
  };

  /**
   * Return public key in DER encoding.
   */
  ECKey.prototype.getPub = function () {
    return this.getPubPoint().getEncoded(this.compressed);
  };

  /**
   * Return public point as ECPoint object.
   */
  ECKey.prototype.getPubPoint = function () {
    if (!this.pub) this.pub = ecparams.getG().multiply(this.priv);

    return this.pub;
  };

  /**
   * Get the pubKeyHash for this key.
   *
   * This is calculated as RIPE160(SHA256([encoded pubkey])) and returned as
   * a byte array.
   */
  ECKey.prototype.getPubKeyHash = function () {
    if (this.pubKeyHash) return this.pubKeyHash;

    return this.pubKeyHash = Bitcoin.Util.sha256ripe160(this.getPub());
  };

  ECKey.prototype.getBitcoinAddress = function () {
    var hash = this.getPubKeyHash();
    var addr = new Bitcoin.Address(hash);
    return addr;
  };

  ECKey.prototype.getExportedPrivateKey = function () {
    var hash = this.priv.toByteArrayUnsigned();
    while (hash.length < 32) hash.unshift(0);
    hash.unshift(Bitcoin.ECKey.privateKeyPrefix); // prepend 0x80 byte
    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
    var bytes = hash.concat(checksum.slice(0,4));
    return Bitcoin.Base58.encode(bytes);
  };

  ECKey.prototype.setPub = function (pub) {
    this.pub = ECPointFp.decodeFrom(ecparams.getCurve(), pub);
  };

  ECKey.prototype.toString = function (format) {
    if (format === "base64") {
      return Crypto.util.bytesToBase64(this.priv.toByteArrayUnsigned());
    } else {
      return Crypto.util.bytesToHex(this.priv.toByteArrayUnsigned());
    }
  };

  ECKey.prototype.sign = function (hash) {
    return ECDSA.sign(hash, this.priv);
  };

  ECKey.prototype.verify = function (hash, sig) {
    return ECDSA.verify(hash, sig, this.getPub());
  };

  /**
   * Parse an exported private key contained in a string.
   */
  ECKey.decodeString = function (string) {
    var bytes = Bitcoin.Base58.decode(string);

    var hash = bytes.slice(0, 33);

    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

    if (checksum[0] != bytes[33] ||
        checksum[1] != bytes[34] ||
        checksum[2] != bytes[35] ||
        checksum[3] != bytes[36]) {
      throw "Checksum validation failed!";
    }

    var version = hash.shift();

    if (version != Bitcoin.ECKey.privateKeyPrefix) {
      throw "Version "+version+" not supported!";
    }

    return hash;
  };

  //
  // From bitaddress.org.
  //
  //
  // Donation Address: 1NiNja1bUmhSoTXozBRBEtR8LeF9TGbZBN
  //
  // Notice of Copyrights and Licenses:
  // ***********************************
  // The bitaddress.org project, software and embedded resources are copyright bitaddress.org.
  // The bitaddress.org name and logo are not part of the open source license.
  //
  // Portions of the all-in-one HTML document contain JavaScript codes that are the copyrights of others.
  // The individual copyrights are included throughout the document along with their licenses.
  // Included JavaScript libraries are separated with HTML script tags.
  //
  // Summary of JavaScript functions with a redistributable license:
  // JavaScript function     License
  // *******************     ***************
  // Array.prototype.map     Public Domain
  // window.Crypto           BSD License
  // window.SecureRandom     BSD License
  // window.EllipticCurve        BSD License
  // window.BigInteger       BSD License
  // window.QRCode           MIT License
  // window.Bitcoin          MIT License
  // window.Crypto_scrypt        MIT License
  //
  // The bitaddress.org software is available under The MIT License (MIT)
  // Copyright (c) 2011-2012 bitaddress.org
  //
  // Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
  // associated documentation files (the "Software"), to deal in the Software without restriction, including
  // without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  // sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject
  // to the following conditions:
  //
  // The above copyright notice and this permission notice shall be included in all copies or substantial
  // portions of the Software.
  //
  // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
  // LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  // IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
  // WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  // SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  //
  // GitHub Repository: https://github.com/pointbiz/bitaddress.org
  //

  // Sipa Private Key Wallet Import Format
  // NOTE:  This looks a lot like: ECKey.prototype.getExportedPrivateKey = function () {
  ECKey.prototype.getBitcoinWalletImportFormat = function () {
    var bytes = this.getBitcoinPrivateKeyByteArray();
    bytes.unshift(Bitcoin.ECKey.privateKeyPrefix); // prepend 0x80 byte
    if (this.compressed) bytes.push(0x01); // append 0x01 byte for compressed format
    var checksum = Crypto.SHA256(Crypto.SHA256(bytes, { asBytes: true }), { asBytes: true });
    bytes = bytes.concat(checksum.slice(0, 4));
    var privWif = Bitcoin.Base58.encode(bytes);
    return privWif;
  };

  ECKey.prototype.getBitcoinPrivateKeyByteArray = function () {
    // Get a copy of private key as a byte array
    var bytes = this.priv.toByteArrayUnsigned();
    // zero pad if private key is less than 32 bytes
    while (bytes.length < 32) bytes.unshift(0x00);
    return bytes;
  };

  // Convert from a checksummed base58 encoding to an ECKey
  ECKey.fromCheckedBase58 = function(string) {
    var base58Checked = Bitcoin.Base58.decode(string);
    base58Checked = base58Checked.splice(1);  // remove the first byte, a version
    var base58 = base58Checked.splice(0, base58Checked.length - 4);  // Remove 4 byte checksum
    return new Bitcoin.ECKey(base58);
  }

  return ECKey;
})();
