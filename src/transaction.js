(function () {
  var Script = Bitcoin.Script;

  var Transaction = Bitcoin.Transaction = function (doc) {
    this.version = 1;
    this.lock_time = 0;
    this.ins = [];
    this.outs = [];
    this.timestamp = null;
    this.block = null;

    if (doc) {
      if (doc.hash) this.hash = doc.hash;
      if (doc.version) this.version = doc.version;
      if (doc.lock_time) this.lock_time = doc.lock_time;
      if (doc.ins && doc.ins.length) {
        for (var i = 0; i < doc.ins.length; i++) {
          this.addInput(new TransactionIn(doc.ins[i]));
        }
      }
      if (doc.outs && doc.outs.length) {
        for (var i = 0; i < doc.outs.length; i++) {
          this.addOutput(new TransactionOut(doc.outs[i]));
        }
      }
      if (doc.timestamp) this.timestamp = doc.timestamp;
      if (doc.block) this.block = doc.block;
    }
  };

  /**
   * Turn transaction data into Transaction objects.
   *
   * Takes an array of plain JavaScript objects containing transaction data and
   * returns an array of Transaction objects.
   */
  Transaction.objectify = function (txs) {
    var objs = [];
    for (var i = 0; i < txs.length; i++) {
      objs.push(new Transaction(txs[i]));
    }
    return objs;
  };

  /**
   * Create a new txin.
   *
   * Can be called with an existing TransactionIn object to add it to the
   * transaction. Or it can be called with a Transaction object and an integer
   * output index, in which case a new TransactionIn object pointing to the
   * referenced output will be created.
   *
   * Note that this method does not sign the created input.
   */
  Transaction.prototype.addInput = function (tx, outIndex) {
    if (arguments[0] instanceof TransactionIn) {
      this.ins.push(arguments[0]);
    } else {
      this.ins.push(new TransactionIn({
        outpoint: {
          hash: tx.hash,
          index: outIndex
        },
        script: new Bitcoin.Script(),
        sequence: 4294967295
      }));
    }
  };

  /**
   * Create a new txout.
   *
   * Can be called with an existing TransactionOut object to add it to the
   * transaction. Or it can be called with an Address object and a BigInteger
   * for the amount, in which case a new TransactionOut object with those
   * values will be created.
   */
  Transaction.prototype.addOutput = function (address, value) {
    if (arguments[0] instanceof TransactionOut) {
      this.outs.push(arguments[0]);
    } else {
      if (value instanceof BigInteger) {
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
      } else if (Bitcoin.Util.isArray(value)) {
        // Nothing to do
      }

      this.outs.push(new TransactionOut({
        value: value,
        script: Script.createOutputScript(address)
      }));
    }
  };

  /**
   * Serialize this transaction.
   *
   * Returns the transaction as a byte array in the standard Bitcoin binary
   * format. This method is byte-perfect, i.e. the resulting byte array can
   * be hashed to get the transaction's standard Bitcoin hash.
   */
  Transaction.prototype.serialize = function ()
  {
    var buffer = [];
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.version)]).reverse());
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.ins.length));
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i];
      buffer = buffer.concat(Crypto.util.base64ToBytes(txin.outpoint.hash));
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.outpoint.index)]).reverse());
      var scriptBytes = txin.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.sequence)]).reverse());
    }
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.outs.length));
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i];
      buffer = buffer.concat(txout.value);
      var scriptBytes = txout.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
    }
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.lock_time)]).reverse());

    return buffer;
  };

  var OP_CODESEPARATOR = 171;

  var SIGHASH_ALL = 1;
  var SIGHASH_NONE = 2;
  var SIGHASH_SINGLE = 3;
  var SIGHASH_ANYONECANPAY = 80;

  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input. This
   * method copies the transaction, makes the necessary changes based on the
   * hashType, serializes and finally hashes the result. This hash can then be
   * used to sign the transaction input in question.
   */
  Transaction.prototype.hashTransactionForSignature =
  function (connectedScript, inIndex, hashType)
  {
    var txTmp = this.clone();

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible
    // incompatibilities.
    /*scriptCode = scriptCode.filter(function (val) {
     return val !== OP_CODESEPARATOR;
     });*/

    // Blank out other inputs' signatures
    for (var i = 0; i < txTmp.ins.length; i++) {
      txTmp.ins[i].script = new Script();
    }

    txTmp.ins[inIndex].script = connectedScript;

    // Blank out some of the outputs
    if ((hashType & 0x1f) == SIGHASH_NONE) {
      txTmp.outs = [];

      // Let the others update at will
      for (var i = 0; i < txTmp.ins.length; i++)
        if (i != inIndex)
          txTmp.ins[i].sequence = 0;
    } else if ((hashType & 0x1f) == SIGHASH_SINGLE) {
      // TODO: Implement
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (hashType & SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
    }

    var buffer = txTmp.serialize();

    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(hashType)]).reverse());

    var hash1 = Crypto.SHA256(buffer, {asBytes: true});

    return Crypto.SHA256(hash1, {asBytes: true});
  };

  /**
   * Calculate and return the transaction's hash.
   */
  Transaction.prototype.getHash = function ()
  {
    var buffer = this.serialize();
    return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
  };

  /**
   * Create a copy of this transaction object.
   */
  Transaction.prototype.clone = function ()
  {
    var newTx = new Transaction();
    newTx.version = this.version;
    newTx.lock_time = this.lock_time;
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i].clone();
      newTx.addInput(txin);
    }
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i].clone();
      newTx.addOutput(txout);
    }
    return newTx;
  };

  /**
   * Analyze how this transaction affects a wallet.
   *
   * Returns an object with properties 'impact', 'type' and 'addr'.
   *
   * 'impact' is an object, see Transaction#calcImpact.
   * 
   * 'type' can be one of the following:
   * 
   * recv:
   *   This is an incoming transaction, the wallet received money.
   *   'addr' contains the first address in the wallet that receives money
   *   from this transaction.
   *
   * self:
   *   This is an internal transaction, money was sent within the wallet.
   *   'addr' is undefined.
   *
   * sent:
   *   This is an outgoing transaction, money was sent out from the wallet.
   *   'addr' contains the first external address, i.e. the recipient.
   *
   * other:
   *   This method was unable to detect what the transaction does. Either it
   */
  Transaction.prototype.analyze = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return null;

    var allFromMe = true,
    allToMe = true,
    firstRecvHash = null,
    firstMeRecvHash = null,
    firstSendHash = null;

    for (var i = this.outs.length-1; i >= 0; i--) {
      var txout = this.outs[i];
      var hash = txout.script.simpleOutPubKeyHash();
      if (!wallet.hasHash(hash)) {
        allToMe = false;
      } else {
        firstMeRecvHash = hash;
      }
      firstRecvHash = hash;
    }
    for (var i = this.ins.length-1; i >= 0; i--) {
      var txin = this.ins[i];
      firstSendHash = txin.script.simpleInPubKeyHash();
      if (!wallet.hasHash(firstSendHash)) {
        allFromMe = false;
        break;
      }
    }

    var impact = this.calcImpact(wallet);

    var analysis = {};

    analysis.impact = impact;

    if (impact.sign > 0 && impact.value.compareTo(BigInteger.ZERO) > 0) {
      analysis.type = 'recv';
      analysis.addr = new Bitcoin.Address(firstMeRecvHash);
    } else if (allFromMe && allToMe) {
      analysis.type = 'self';
    } else if (allFromMe) {
      analysis.type = 'sent';
      // TODO: Right now, firstRecvHash is the first output, which - if the
      //       transaction was not generated by this library could be the
      //       change address.
      analysis.addr = new Bitcoin.Address(firstRecvHash);
    } else  {
      analysis.type = "other";
    }

    return analysis;
  };

  /**
   * Get a human-readable version of the data returned by Transaction#analyze.
   *
   * This is merely a convenience function. Clients should consider implementing
   * this themselves based on their UI, I18N, etc.
   */
  Transaction.prototype.getDescription = function (wallet) {
    var analysis = this.analyze(wallet);

    if (!analysis) return "";

    switch (analysis.type) {
    case 'recv':
      return "Received with "+analysis.addr;
      break;

    case 'sent':
      return "Payment to "+analysis.addr;
      break;

    case 'self':
      return "Payment to yourself";
      break;

    case 'other':
    default:
      return "";
    }
  };

  /**
   * Get the total amount of a transaction's outputs.
   */
  Transaction.prototype.getTotalOutValue = function () {
    var totalValue = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      totalValue = totalValue.add(Bitcoin.Util.valueToBigInt(txout.value));
    }
    return totalValue;
  };

   /**
    * Old name for Transaction#getTotalOutValue.
    *
    * @deprecated
    */
   Transaction.prototype.getTotalValue = Transaction.prototype.getTotalOutValue;

  /**
   * Calculates the impact a transaction has on this wallet.
   *
   * Based on the its public keys, the wallet will calculate the
   * credit or debit of this transaction.
   *
   * It will return an object with two properties:
   *  - sign: 1 or -1 depending on sign of the calculated impact.
   *  - value: amount of calculated impact
   *
   * @returns Object Impact on wallet
   */
  Transaction.prototype.calcImpact = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return BigInteger.ZERO;

    // Calculate credit to us from all outputs
    var valueOut = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      var hash = Crypto.util.bytesToBase64(txout.script.simpleOutPubKeyHash());
      if (wallet.hasHash(hash)) {
        valueOut = valueOut.add(Bitcoin.Util.valueToBigInt(txout.value));
      }
    }

    // Calculate debit to us from all ins
    var valueIn = BigInteger.ZERO;
    for (var j = 0; j < this.ins.length; j++) {
      var txin = this.ins[j];
      var hash = Crypto.util.bytesToBase64(txin.script.simpleInPubKeyHash());
      if (wallet.hasHash(hash)) {
        var fromTx = wallet.txIndex[txin.outpoint.hash];
        if (fromTx) {
          valueIn = valueIn.add(Bitcoin.Util.valueToBigInt(fromTx.outs[txin.outpoint.index].value));
        }
      }
    }
    if (valueOut.compareTo(valueIn) >= 0) {
      return {
        sign: 1,
        value: valueOut.subtract(valueIn)
      };
    } else {
      return {
        sign: -1,
        value: valueIn.subtract(valueOut)
      };
    }
  };

  var TransactionIn = Bitcoin.TransactionIn = function (data)
  {
    this.outpoint = data.outpoint;
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }
    this.sequence = data.sequence;
  };

  TransactionIn.prototype.clone = function ()
  {
    var newTxin = new TransactionIn({
      outpoint: {
        hash: this.outpoint.hash,
        index: this.outpoint.index
      },
      script: this.script.clone(),
      sequence: this.sequence
    });
    return newTxin;
  };

  var TransactionOut = Bitcoin.TransactionOut = function (data)
  {
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }

    if (Bitcoin.Util.isArray(data.value)) {
      this.value = data.value;
    } else if ("string" == typeof data.value) {
      var valueHex = (new BigInteger(data.value, 10)).toString(16);
      while (valueHex.length < 16) valueHex = "0" + valueHex;
      this.value = Crypto.util.hexToBytes(valueHex);
    }
  };

  TransactionOut.prototype.clone = function ()
  {
    var newTxout = new TransactionOut({
      script: this.script.clone(),
      value: this.value.slice(0)
    });
    return newTxout;
  };


  //
  // Utility functions for parsing
  //
  function uint(f, size) {
    if (f.length < size)
      return 0;
    var bytes = f.slice(0, size);
    var pos = 1;
    var n = 0;
    for (var i = 0; i < size; i++) {
      var b = f.shift();
      n += b * pos;
      pos *= 256;
    }
    return size <= 4 ? n : bytes;
  }

  function u8(f)  { return uint(f,1); }
  function u16(f) { return uint(f,2); }
  function u32(f) { return uint(f,4); }
  function u64(f) { return uint(f,8); }

  function errv(val) {
    return (val instanceof BigInteger || val > 0xffff);
  }

  function readBuffer(f, size) {
    var res = f.slice(0, size);
    for (var i = 0; i < size; i++) f.shift();
    return res;
  }

  function readString(f) {
    var len = readVarInt(f);
    if (errv(len)) return [];
    return readBuffer(f, len);
  }

  function readVarInt(f) {
    var t = u8(f);
    if (t == 0xfd) return u16(f); else
    if (t == 0xfe) return u32(f); else
    if (t == 0xff) return u64(f); else
    return t;
  }

  Transaction.deserialize = function(bytes) {
    var sendTx = new Bitcoin.Transaction();

    var f = bytes.slice(0);
    var tx_ver = u32(f);
    var vin_sz = readVarInt(f);
    if (errv(vin_sz))
        return null;

    for (var i = 0; i < vin_sz; i++) {
        var op = readBuffer(f, 32);
        var n = u32(f);
        var script = readString(f);
        var seq = u32(f);
        var txin = new Bitcoin.TransactionIn({
            outpoint: {
                hash: Crypto.util.bytesToBase64(op),
                index: n
            },
            script: new Bitcoin.Script(script),
            sequence: seq
        });
        sendTx.addInput(txin);
    }

    var vout_sz = readVarInt(f);

    if (errv(vout_sz))
        return null;

    for (var i = 0; i < vout_sz; i++) {
        var value = u64(f);
        var script = readString(f);

        var txout = new Bitcoin.TransactionOut({
            value: value,
            script: new Bitcoin.Script(script)
        });

        sendTx.addOutput(txout);
    }
    var lock_time = u32(f);
    sendTx.lock_time = lock_time;
    return sendTx;
  };

  // Enumerate all the inputs, and find any which require a key
  // which matches the input key.
  //
  // Returns the number of inputs signed.
  Bitcoin.Transaction.prototype.signWithKey = function(key) {
    var signatureCount = 0;
  
    var keyHash = key.getPubKeyHash();
    for (var index = 0; index < this.ins.length; ++index) {
      var input = this.ins[index];
      var inputScript = input.script;
  
      if (inputScript.simpleOutHash().compare(keyHash)) {
        var hashType = 1;  // SIGHASH_ALL
        var hash = this.hashTransactionForSignature(inputScript, index, hashType);
        var signature = key.sign(hash);
        signature.push(parseInt(hashType, 10));
        var pubKey = key.getPub();
        var script = new Bitcoin.Script();
        script.writeBytes(signature);
        script.writeBytes(pubKey);
        this.ins[index].script = script;
        signatureCount++;
      }
    }
    return signatureCount;
  };

  // Sign a transaction for a P2SH multi-signature input.
  //
  // Enumerates all the inputs, and find any which need our signature.
  // This function does not require that all signatures are applied at the
  // same time.  You can sign it once, then call it again later to sign
  // again.  When this happens, we leave the scriptSig padded with OP_0's
  // where the missing signatures would go.  This allows to us to create
  // a valid, parseable transaction that can be passed around in this
  // intermediate, partially signed state.
  //
  // Returns the number of signnatures applied in this pass (kind of meaningless)
  Transaction.prototype.signWithMultiSigScript = function(keyArray, redeemScriptBytes) {
    var hashType = 1;  // SIGHASH_ALL
    var signatureCount = 0;
  
    // First figure out how many signatures we need.
    var redeemScript = new Bitcoin.Script(redeemScriptBytes);
    var numSigsRequired = redeemScript.chunks[0] - Bitcoin.Opcode.map.OP_1 + 1;
    if (numSigsRequired < 0 || numSigsRequired > 3) {
      throw "Can't determine required number of signatures";
    }
    var redeemScriptHash = Bitcoin.Util.sha256ripe160(redeemScriptBytes);
  
    var self = this;
    this.ins.forEach(function(input, inputIndex) {
      var inputScript = input.script;
  
      // This reedem script applies under two cases:
      //   a) The input has no signatures yet, is a P2SH input script, and hash a hash matching this redeemscript.
      //   b) The input some signatures already, but needs more.
  
      if (inputScript.getOutType() == 'P2SH' &&
          inputScript.simpleOutHash().compare(redeemScriptHash)) {
        // This is a matching P2SH input.  Create a template Script with
        // 0's as placeholders for the signatures.
  
        var script = new Bitcoin.Script();
        script.writeOp(Bitcoin.Opcode.map.OP_0);  // BIP11 requires this leading OP_0.
        for (var index = 0; index < numSigsRequired; ++index) {
          script.writeOp(Bitcoin.Opcode.map.OP_0);  // A placeholder for each sig
        }
        script.writeBytes(redeemScriptBytes);  // The redeemScript itself.
        inputScript = self.ins[inputIndex].script = script;
      }
  
      // Check if the input script looks like a partially signed template.
      // If so, apply as many signatures as we can.
      if ((inputScript.chunks.length == numSigsRequired + 2) &&
          (inputScript.chunks[0] == Bitcoin.Opcode.map.OP_0) &&
          (inputScript.chunks[numSigsRequired+1].compare(redeemScriptBytes))) {
        var keyIndex = 0;  // keys we've used so far for this input.
  
        var hashToSign = self.hashTransactionForSignature(redeemScript, inputIndex, hashType);
  
        // Create a new script, insert the leading OP_0.
        var script = new Bitcoin.Script();
        script.writeOp(Bitcoin.Opcode.map.OP_0);
  
        // For the rest of the sigs, either copy or insert a new one.
        for (var index = 1; index < 1 + numSigsRequired; ++index) {
          if (inputScript.chunks[index] != 0) {  // Already signed case
            script.writeBytes(inputScript.chunks[index]);
          } else {
            var signed = false;
            while (!signed && keyIndex < keyArray.length) {
              var key = keyArray[keyIndex++];  // increment keys tried
              var signature = key.sign(hashToSign);
              signature.push(parseInt(hashType, 10));
  
              // Verify that this signature hasn't already been applied.
              var isDuplicateSignature = false;
              for (var index2 = 1; index2 < 1 + numSigsRequired; ++index2) {
                if (signature.compare(inputScript.chunks[index2])) {
                  isDuplicateSignature = true;
                  break;
                }
              }
              if (isDuplicateSignature) {
                continue;  // try another key
              }
              script.writeBytes(signature);  // Apply the signature
              signatureCount++;
              signed = true;
            }
            if (!signed) {
              // We don't have any more keys to sign with!
              // Write another placeholder.
              script.writeOp(Bitcoin.Opcode.map.OP_0);
            }
          }
        }
        // Finally, record the redeemScript itself and we're done.
        script.writeBytes(redeemScriptBytes);
        self.ins[inputIndex].script = script;
      }
    });
    return signatureCount;
  }

  /**
   * Create a new txout.
   *
   * Can be called with an existing TransactionOut object to add it to the
   * transaction. Or it can be called with an Address object and a BigInteger
   * for the amount, in which case a new TransactionOut object with those
   * values will be created.
   */
  Transaction.prototype.addOutput = function (address, value) {
    if (arguments[0] instanceof Bitcoin.TransactionOut) {
      this.outs.push(arguments[0]);
    } else {
      if (value instanceof BigInteger) {
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
      } else if (Bitcoin.Util.isArray(value)) {
        // Nothing to do
      } else if ( typeof(value) == 'number') {
        value = BigInteger.valueOf(value);
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
      }
  
      this.outs.push(new Bitcoin.TransactionOut({
        value: value,
        script: Bitcoin.Script.createOutputScript(address)
      }));
    }
  };
})();
