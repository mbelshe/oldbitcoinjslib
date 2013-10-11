#!/bin/sh

export SRCDIR=.

export FILES="\
    $SRCDIR/src/header.js \
    $SRCDIR/src/crypto-js/crypto.js \
    $SRCDIR/src/crypto-js/sha256.js \
    $SRCDIR/src/crypto-js/ripemd160.js \
    $SRCDIR/src/jsbn/prng4.js \
    $SRCDIR/src/jsbn/rng.js \
    $SRCDIR/src/jsbn/jsbn.js \
    $SRCDIR/src/jsbn/jsbn2.js \
    $SRCDIR/src/jsbn/ec.js \
    $SRCDIR/src/jsbn/sec.js \
    $SRCDIR/src/events/eventemitter.js \
    $SRCDIR/src/util.js \
    $SRCDIR/src/base58.js \
    $SRCDIR/src/address.js \
    $SRCDIR/src/ecdsa.js \
    $SRCDIR/src/eckey.js \
    $SRCDIR/src/opcode.js \
    $SRCDIR/src/script.js \
    $SRCDIR/src/transaction.js \
    $SRCDIR/src/txdb.js \
    $SRCDIR/src/bitcoin.js"

echo "Building build/bitcoinjs-lib.js"
cat $FILES > build/bitcoinjs-lib.js 
echo "Building build/bitcoinjs-lib.min.js"
uglifyjs -m -o build/bitcoinjs-lib.min.js $FILES

