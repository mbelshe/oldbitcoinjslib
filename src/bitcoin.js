(function() {
  /*
   * BitGo additions for globally selecting network type
   */
  Bitcoin.setNetwork = function(network) {
    if (network == 'prod') {
      Bitcoin.Address.pubKeyHashVersion = 0x00;
      Bitcoin.Address.p2shVersion    = 0x5;
      Bitcoin.ECKey.privateKeyPrefix = 0x80;
    } else {
      // test network
      Bitcoin.Address.pubKeyHashVersion = 0x6f;
      Bitcoin.Address.p2shVersion    = 0xc4;
      Bitcoin.ECKey.privateKeyPrefix = 0xef;
    }
  }
  Bitcoin.setNetwork('prod');
  
  // WARNING:  It's bad form to set a function on the global array prototype here.
  Array.prototype.compare = function (array) {
    // if the other array is a falsy value, return
    if (!array)
      return false;
  
    // compare lengths - can save a lot of time
    if (this.length != array.length)
      return false;
  
    for (var i = 0; i < this.length; i++) {
      // Check if we have nested arrays
      if (this[i] instanceof Array && array[i] instanceof Array) {
        // recurse into the nested arrays
        if (!this[i].compare(array[i]))
          return false;
        }
        else if (this[i] != array[i]) {
          // Warning - two different object instances will never be equal: {x:20} != {x:20}
          return false;
        }
      }
    return true;
  }
  
  // So we can load into node.
  if (typeof(module) == 'object') {
    module.exports = function(network) {
      sjcl = require('sjcl');

      // The SJCL guys screwed up how they export modules; so two imports
      // both need to separately initialize the randomness.
      var crypto = require('crypto');
      var buf = Bitcoin.Util.hexToBytes(crypto.randomBytes(1024/8).toString('hex'));
      sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");

      Bitcoin.setNetwork(network);
      return Bitcoin;
    }
  }
})();
