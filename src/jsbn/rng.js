// Use SJCL for our random source

function SecureRandom() {
}

SecureRandom.prototype.clientSideRandomInit = function() {
  sjcl.random.startCollectors();  // do this only once
}

SecureRandom.prototype.nextBytes = function(arrayToFillRandomly) {
  var length = arrayToFillRandomly.length
  var randomArray = sjcl.random.randomWords(length);
  for (var index = 0; index < length; ++index) {
    if (randomArray[index] < 0) {
      randomArray[index] = -randomArray[index];
    }
    arrayToFillRandomly[index] = randomArray[index] % 256;
  }
}
