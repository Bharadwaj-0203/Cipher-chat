const crypto = require('crypto');

class EncryptionManager {
  
  encryptMessage = (message, publicKey) => {
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message));
    return encrypted.toString('base64');
  };

  decryptMessage = (encryptedMessage, privateKey) => {
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, 'base64'));
    return decrypted.toString();
  };
}

module.exports = new EncryptionManager();