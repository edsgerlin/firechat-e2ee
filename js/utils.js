'use strict';
const RSA_ALGORITHM = {
  name: 'RSA-OAEP',
  modulusLength: 4096,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-512' }
};

const SHA_ALGORITHM = {
  name: 'SHA-256'
};

/**
 * Convert base64url encoded string to base64 encoded.
 * @param {string} encodedString -
 */
function normalizeBase64urlEncode(encodedString) {
  return encodedString.replace(/-/g, '+').replace(/_/g, '/').concat('='.repeat(4 - (encodedString.length % 4)));
}

function base64urlToSHA256(encodedString) {
  return subtle.digest(
    SHA_ALGORITHM,
    base64js.toByteArray(normalizeBase64urlEncode(encodedString))
  ).then(hash => new Promise((resolve, reject) => {
    const sha256sum = new Uint8Array(hash).reduce(reduceToHex, '');
    resolve(sha256sum);
  }));
}

/**
 * Convert a Uint8Array Array to hex string.
 * @param {string} previousValue -
 * @param {number} currentValue -
 */
function reduceToHex(previousValue, currentValue) {
  return previousValue + (currentValue.toString(16).length === 2 ? '' : '0') + currentValue.toString(16);
}

const crypto = window.crypto;
const subtle = crypto.subtle;

const database = firebase.database();
class UserViewModel {
  constructor(messageList) {
    this._key = undefined;
    this.messageList = messageList;
    this.id = ko.observable("");
    this.publicKey = ko.observable("");
    this.privateKey = ko.observable("");
    this.generated = ko.observable(false);
    this.uploaded = ko.observable(false);
  }
  generateRSAKey() {
    subtle.generateKey(
      RSA_ALGORITHM,
      true,
      ['encrypt', 'decrypt']
    ).then(key => this.key = key);
  }
  exportPrivate(privateKey) {
    subtle.exportKey('jwk', privateKey).then(jwk => this.privateKey(JSON.stringify(jwk)));
  }
  exportPublic(publicKey) {
    subtle.exportKey('jwk', publicKey).then(jwk => new Promise(
      (resolve, reject) => {
        this.publicKey(JSON.stringify(jwk));
        resolve(jwk.n);
      }
    )).then(base64urlToSHA256).then(hash => {
      this.id(hash);
      this.generated(true);
    });
  }
  set key(key) {
    this._key = key;
    this.exportPrivate(this._key.privateKey);
    this.exportPublic(this._key.publicKey);
  }
  get key() {
    return this._key;
  }
  upload() {
    console.log(JSON.parse(this.publicKey()));
    database.ref('/users/' + this.id()).set({
      key: this.publicKey()
    });
    database.ref('/users/' + this.id() + '/messages').on('child_added', function (child) {
      const val = child.val();
      console.log(val);
      messageList.messages.unshift(val.message);
    });
    this.uploaded(true);
  }
}

class ReceiverViewModel {
  constructor(user) {
    this._publicKey = undefined;
    this.id = ko.observable("");
    this.publicKey = ko.observable("");
    this.message = ko.observable("");
    this.downloading = ko.observable(false);
    this.user = user;
  }
  download() {
    const id = this.id();
    if (id.length === 64 && id.match(/^[0-9a-f]+$/)) {
      this.downloading(true);
      database.ref('/users/' + this.id()).once('value').then(value => {
        this.publicKey(value.val().key);
        subtle.importKey('jwk',
          JSON.parse(this.publicKey()),
          RSA_ALGORITHM,
          true,
          ['encrypt']
        ).then(publicKey => {
          this._publicKey = publicKey;
          this.downloading(false);
        });
      });
    }
    else {
      this.id('Invalid Sparkle ID!');
    }
  }

  sendMessage() {
    const message = this.message();
    database.ref('/users/' + this.id() + '/messages').push({ message: message });
  }
}

class MessageList {
  constructor() {
    this.messages = ko.observableArray();
  }
}