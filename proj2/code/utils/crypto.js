// Wrapper functions for Stanford JavaScript Crypto Library

import sjcl from "./sjcl";

export function generateRandomness() {
  return sjcl.codec.hex.fromBits(sjcl.random.randomWords(8));
}

export function KDF(password, salt) {
  // takes a string as input
  // outputs a hex-encoded string
  const bitarrayOutput = sjcl.misc.pbkdf2(password, salt, 100000);
  return sjcl.codec.hex.fromBits(bitarrayOutput);
}

export function checkPassword(password, dbResult) {
  const inputKDFResult = KDF(password, dbResult.salt);
  if(inputKDFResult == dbResult.hashedPassword) {
    return true;
  }
  return false;
}

export function HMAC(key, data) {
  // Returns the HMAC on the data.
  // key is a hex-encoded string
  // data is a string (any encoding is fine)
  let hmacObject = new sjcl.misc.hmac(sjcl.codec.hex.toBits(key), sjcl.hash.sha256);
  const bitarrayOutput = hmacObject.encrypt(data);
  return sjcl.codec.hex.fromBits(bitarrayOutput);
}
