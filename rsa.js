const crypto = require('crypto');

function generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });

    return { 
        publicKey: publicKey.toString("base64").replace(/\r?\n|\r/g, ''), 
        privateKey: privateKey.toString("base64").replace(/\r?\n|\r/g, '') 
    };
}

function encrypt(publicKeyStr, value) {
    const publicKey = crypto.createPublicKey({
        key: Buffer.from(publicKeyStr, 'base64'),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        format: 'der',
        type:'spki'
    });
    
    const encryptedBuffer = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(value)); 

    return encryptedBuffer.toString('base64');
}

function decrypt(privateKeyStr, value) {
    const publicKeyFromStr = crypto.createPrivateKey({
        key: Buffer.from(privateKeyStr, 'base64'),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        format: 'der',
        type:'pkcs8'
    });

    const decryptedBuffer = crypto.privateDecrypt({
        key: publicKeyFromStr,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING  
    }, Buffer.from(value, 'base64'));

    return decryptedBuffer.toString('utf8');
}

function main() {
    const originalMessage = "This `s RSA Encryption Using PUBL1C/PRIVAT3 Key$";
    console.log("Original Message: ", originalMessage);
    
    const keys = generateKeys();
    console.log("Public Key: ", keys.publicKey);
    console.log("Private Key: ", keys.privateKey);
    
    const encryptedData = encrypt(keys.publicKey, originalMessage);
    console.log("Encrypted Data: ", encryptedData);
 
    const decryptedData = decrypt(keys.privateKey, encryptedData);
    console.log("Decrypted Data: ", decryptedData);
}

main();
