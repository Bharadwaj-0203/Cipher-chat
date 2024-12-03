const crypto = require('crypto');

class EncryptionManager {
  generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }
  
  encryptMessage = (message, publicKey) => {
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message));
    return encrypted.toString('base64');
  };

  decryptMessage = (encryptedMessage, privateKey) => {
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, 'base64'));
    return decrypted.toString();
  };

  hashPassword(password) {
    const salt = crypto.randomBytes(32);
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha256');
    return {
      hash: hash.toString('hex'),
      salt: salt.toString('hex')
    };
  }

  verifyPassword(password, hash, salt) {
    const verifyHash = crypto.pbkdf2Sync(
      password, 
      Buffer.from(salt, 'hex'), 
      10000, 
      64, 
      'sha256'
    ).toString('hex');
    return verifyHash === hash;
  }
}

module.exports = new EncryptionManager();