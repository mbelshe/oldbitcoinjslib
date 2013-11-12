(function () {

  var Address = Bitcoin.Address = function (input, version) {
    if ("string" == typeof input) {
      this.fromString(input);
      return this;
    }
 
    if (input instanceof Bitcoin.ECKey) {
      input = input.getPubKeyHash();
    }

    if (!(input instanceof Array)) {
      throw "can't convert to address";
    }

    this.hash = input;
    this.version = version || Bitcoin.Address.pubKeyHashVersion;
  };

  /**
   * Serialize this object as a standard Bitcoin address.
   *
   * Returns the address as a base58-encoded string in the standardized format.
   */
  Address.prototype.toString = function () {
    // Get a copy of the hash
    var hash = this.hash.slice(0);

    // Version
    hash.unshift(this.version);
  
    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
  
    var bytes = hash.concat(checksum.slice(0,4));
  
    return Bitcoin.Base58.encode(bytes);
  };
  
  Address.prototype.getHashBase64 = function () {
    return Crypto.util.bytesToBase64(this.hash);
  };
  
  Address.decodeString = function(string) {
    throw "Bitcoin.Address.decodeString is depricated";
  }
  
  /**
   * Parse a Bitcoin address contained in a string.
   */
  Address.prototype.fromString = function (string) {
    var bytes = Bitcoin.Base58.decode(string);
  
    var hash = bytes.slice(0, 21);
  
    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
  
    if (checksum[0] != bytes[21] ||
        checksum[1] != bytes[22] ||
        checksum[2] != bytes[23] ||
        checksum[3] != bytes[24]) {
      throw "Checksum validation failed!";
    }
  
    this.version = hash.shift();
    this.hash = hash;
  
    if (this.version != Bitcoin.Address.pubKeyHashVersion &&
        this.version != Bitcoin.Address.p2shVersion) {
      throw "Version " + this.version + " not supported!";
    }
  };
  
  Address.createMultiSigAddress = function(keys, numRequired) {
    if (numRequired < 0 || numRequired > keys.length || numRequired > 16) { throw "invalid number of keys required" }
    for (var index = 0; index < keys.length; ++index) {
      if (Object.prototype.toString.call(keys[index]) != '[object Array]') { throw "pub keys are not of right type"; }
    }
  
    var redeemScript = Bitcoin.Script.createMultiSigScript(numRequired, keys);
    var bytes = redeemScript.buffer;
    var hash = Bitcoin.Util.sha256ripe160(bytes);
    var address = new Bitcoin.Address(hash);
    address.redeemScript = bytes;
    address.version = Bitcoin.Address.p2shVersion;
    return address;
  }
  
  Address.prototype.isP2SHAddress = function() {
    return this.version == Bitcoin.Address.p2shVersion;
  }
  
  Address.prototype.isPubKeyHashAddress = function() {
    return this.version == Bitcoin.Address.pubKeyHashVersion;
  }
  
  Address.validate = function(addressString)  {
    try {
      var address = new Bitcoin.Address(addressString);
    } catch (e) {
      return false;  // invalid address.
    }
    return true;
  }
  
  // Create a bitcoin address from a public key.
  Address.fromPubKey = function(pubKey) {
    return new Bitcoin.Address(Bitcoin.Util.sha256ripe160(pubKey));
  }
})();
