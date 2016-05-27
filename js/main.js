/**
 * Convert base64url encoded string to base64 encoded.
 * @param {string} encodedString -
 */
function normalizeBase64urlEncode(encodedString) {
  return encodedString.replace(/-/g, '+').replace(/_/g, '/').concat('='.repeat(4 - (encodedString.length % 4)));
}

/**
 * Convert a Uint8Array Array to hex string.
 * @param {string} previousValue -
 * @param {number} currentValue -
 */
function reduceToHex(previousValue, currentValue) {
  return previousValue + (currentValue.toString(16).length === 2 ? '' : '0') + currentValue.toString(16);
}

const RSA_ALGORITHM = {
  name: 'RSA-OAEP',
  modulusLength: 4096,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-512' }
};

const SHA_ALGORITHM = {
  name: 'SHA-256'
};

function generateRSAKey() {
  document.getElementById('generate-key').disabled = true;
  window.crypto.subtle.generateKey(
    RSA_ALGORITHM,
    true,
    ['encrypt', 'decrypt']
  ).then(key => new Promise(
    (resolve, reject) => {
      const privateKeyPromise = window.crypto.subtle.exportKey('jwk', key.privateKey);
      privateKeyPromise.then(jwk => document.getElementById('private-key').value = JSON.stringify(jwk));
      const publicKeyPromise = window.crypto.subtle.exportKey('jwk', key.publicKey);
      publicKeyPromise
        .then(jwk => new Promise(
          (resolve, reject) => {
            document.getElementById('public-key').value = JSON.stringify(jwk);
            resolve(jwk.n);
          }
        )).then(base64urlToSHA256).then(hash => {
          document.getElementById('sparkle-id').value = hash;
          document.getElementById('generate-key').disabled = false;
        }).catch(reject);
    }
  ));
}

function loadRSAKey() {
  const n = JSON.parse(
    document.getElementById('public-key').value).n;
  document.getElementById('load-key').disabled = true;
  base64urlToSHA256(n).then(sha256sum => document.getElementById('sparkle-id').value = sha256sum);
  
  window.crypto.subtle.importKey('jwk',
    JSON.parse(
      document.getElementById('public-key').value),
    RSA_ALGORITHM,
    true,
    ['encrypt']
  ).then(public => console.log(public));
}

function loadRSAPublic(id) {
  return window.crypto.subtle.importKey('jwk',
    JSON.parse(
      document.getElementById(id).value),
    RSA_ALGORITHM,
    true,
    ['encrypt']
  );
}

function loadRSAPrivate(id) {
  return window.crypto.subtle.importKey('jwk',
    JSON.parse(
      document.getElementById(id).value),
    RSA_ALGORITHM,
    true,
    ['decrypt']
  );
}

function base64urlToSHA256(encodedString) {
  return window.crypto.subtle.digest(
    SHA_ALGORITHM,
    base64js.toByteArray(normalizeBase64urlEncode(encodedString))
  ).then(hash => new Promise((resolve, reject) => {
    const sha256sum = new Uint8Array(hash).reduce(reduceToHex, '');
    resolve(sha256sum);
  }));
}