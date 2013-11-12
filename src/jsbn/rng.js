// Use SJCL for our random source

sjcl.random.startCollectors();  // do this only once

function SecureRandom() {
}

SecureRandom.prototype.nextBytes = function(arrayToFillRandomly) {
  var length = arrayToFillRandomly.length
  var randomArray = sjcl.random.randomWords(length);
  for (var index = 0; index < length; ++index) {
    arrayToFillRandomly[index] = randomArray[index] % 256;
  }
}
