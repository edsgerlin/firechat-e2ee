'use strict';
const crypto = window.crypto;
const subtle = crypto.subtle;
const database = firebase.database();
const keyUsage = ['encrypt', 'decrypt'];
// ucs-2 string to base64 encoded ascii
function utoa(str) {
  return window.btoa(unescape(encodeURIComponent(str)));
}
// base64 encoded ascii to ucs-2 string
function atou(str) {
  return decodeURIComponent(escape(window.atob(str)));
}
/**
 * @type {Algorithm}
 */
const RSA_ALGORITHM = {
  name: 'RSA-OAEP',
  modulusLength: 4096,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-512' }
};

/**
 * @type {Algorithm}
 */
const SHA_ALGORITHM = {
  name: 'SHA-256'
};

/**
 * @type {Algorithm}
 */
const AES_ALGORITHM = {
  name: 'AES-GCM',
  length: 256
};



function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}


/**
 * Convert base64url encoded string to base64 encoded.
 * @param {string} encodedString -
 */
function normalizeBase64urlEncode(encodedString) {
  return encodedString.replace(/-/g, '+').replace(/_/g, '/').concat('='.repeat(4 - (encodedString.length % 4)));
}

/**
 * Convert base64 encoded string to base64url encoded.
 * @param {string} encodedString -
 */
function abnormalizeBase64Encode(encodedString) {
  const s =
    encodedString.replace(/\+/g, '-').replace(/\//g, '_').replace('=', '');
  console.log(s);
  return s;
}


/**
 * Compute sha256 digest for base64url encoded binary blob.
 * @param {string} encodedString -
 */
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
      keyUsage
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
    database.ref('/users/' + this.id()).set({
      key: this.publicKey()
    });
    database.ref('/users/' + this.id() + '/messages').on('child_added', child => {
      const messageobject = child.val();

      let data = {
        iv: messageobject.iv,
        encryptedKey: messageobject.encryptedKey,
        ciphertext: messageobject.ciphertext,
        sender: messageobject.sender,
        receiver: messageobject.receiver
      };
      console.log('data' + JSON.stringify(data));
      const rawkeyPromise = subtle.decrypt(
        { name: 'RSA-OAEP' },
        this.key.privateKey,
        base64js.toByteArray(data.encryptedKey)
      )
      console.log('rawkeyPromise' + rawkeyPromise);
      const keyPromise = rawkeyPromise.then(rawKey => {
        console.log("key decrypted = " + base64js.fromByteArray(new Uint8Array(rawKey)));
        data.key = base64js.fromByteArray(new Uint8Array(rawKey));

        return subtle.importKey('jwk', {
          kty: 'oct',
          k: abnormalizeBase64Encode(data.key),
          alg: 'A256GCM',
          ext: true
        }, { name: 'AES-GCM' },
          true,
          keyUsage
        );
      });
      const plaintextPromise = keyPromise.then(key => {
        return subtle.decrypt({
          name: 'AES-GCM',
          iv: base64js.toByteArray(data.iv)
        },
          key,
          base64js.toByteArray(data.ciphertext)
        );
      });
      plaintextPromise.then(plaintextBuffer => {
        const plaintext = base64js.fromByteArray(new Uint8Array(plaintextBuffer));
        data.plaintext = atou(plaintext);
        messageList.messages.unshift(data);
      });
    });
    this.uploaded(true);
  }
}

class ReceiverViewModel {
  constructor(sender) {
    this._publicKey = undefined;
    this.id = ko.observable("");
    this.publicKey = ko.observable("");
    this.message = ko.observable("");
    this.downloading = ko.observable(false);
    this.downloaded = ko.observable(false);
    this.sending = ko.observable(false);
    this.sender = sender;
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
          this.downloaded(true);
        });
      });
    }
    else {
      this.id('Invalid Sparkle ID!');
    }
  }

  sendMessage() {
    this.sending(true);
    const message = this.message();
    const iv = generateIV();
    const encodedIV = base64js.fromByteArray(iv);
    const sender = this.sender.id();
    const receiver = this.id();
    subtle.generateKey(AES_ALGORITHM, true, keyUsage).then(key => {
      const encryptedKeyPromise = subtle.exportKey('jwk', key).then(exportedKey => {
        const encodedKey = normalizeBase64urlEncode(exportedKey.k);
        const keyBuffer = base64js.toByteArray(encodedKey);
        return subtle.encrypt(
          { name: 'RSA-OAEP' },
          this._publicKey,
          keyBuffer
        );
      });
      const encryptedMessagePromise = subtle.encrypt({
        name: 'AES-GCM',
        iv: iv,
        length: 256
      },
        key,
        base64js.toByteArray(utoa(message))
      );
      Promise.all([encryptedKeyPromise, encryptedMessagePromise]).then(result => {
        const encryptedKey = base64js.fromByteArray(new Uint8Array(result[0]));
        const encryptedMessage = base64js.fromByteArray(new Uint8Array(result[1]));
        const messageobject = {
          iv: encodedIV,
          encryptedKey: encryptedKey,
          ciphertext: encryptedMessage,
          sender: sender,
          receiver: receiver
        };
        console.log(`message to be sent ${JSON.stringify(messageobject)}`);
        database.ref('/users/' + this.id() + '/messages').push(messageobject);
        this.sending(false);
      });

    });

  }
}

class MessageList {
  constructor() {
    this.messages = ko.observableArray();
  }
  showDetail(data) {
    const messageViewModel = ko.dataFor(document.getElementById('message-view'));
    messageViewModel.plaintext(data.plaintext);
    messageViewModel.ciphertext(data.ciphertext);
    messageViewModel.key(data.key);
    messageViewModel.encryptedKey(data.encryptedKey);
    messageViewModel.iv(data.iv);
    messageViewModel.sender(data.sender);
    messageViewModel.receiver(data.receiver);
  }
}


function encryptMessage(receiver, message) {
  const messageViewModel = ko.dataFor(document.getElementById('message-view'));
  messageViewModel.sender(receiver.sender.id());
  messageViewModel.receiver(receiver.id());
  messageViewModel.plaintext(message);
  const iv = generateIV();
  messageViewModel.iv(base64js.fromByteArray(iv));

  console.log('iv=' + messageViewModel.iv());
  subtle.generateKey(AES_ALGORITHM, true, keyUsage).then(key => {
    subtle.exportKey('jwk', key).then(key => {
      messageViewModel.key(normalizeBase64urlEncode(key.k));
      console.log('key:' + messageViewModel.key());
      subtle.encrypt(
        { name: 'RSA-OAEP' },
        receiver._publicKey,
        base64js.toByteArray(messageViewModel.key())
      ).then(encryptedKey => {
        messageViewModel.encryptedKey(base64js.fromByteArray(new Uint8Array(encryptedKey)));
        console.log('encryptedkey:' + messageViewModel.encryptedKey());
      });
    });

    subtle.encrypt({
      name: 'AES-GCM',
      iv: iv,
      length: 256
    },
      key,
      base64js.toByteArray(utoa(message))
    ).then(encrypted => {
      messageViewModel.ciphertext(base64js.fromByteArray(new Uint8Array(encrypted)));
      console.log('ciphertext:' + messageViewModel.ciphertext());
    });
  });
  return messageViewModel;
}


class MessageViewModel {
  constructor() {
    this.plaintext = ko.observable("");
    this.ciphertext = ko.observable("");
    this.key = ko.observable("");
    this.encryptedKey = ko.observable("");
    this.iv = ko.observable("");
    this.sender = ko.observable("");
    this.receiver = ko.observable("");
  }
}