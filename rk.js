// Global variables
let rsaKeys = null;
let aesKey = null;
let iv = null;
let encryptedData = {};

/**
 * Generate RSA public/private key pair
 */
function generateKeys() {
    try {
        const encrypt = new JSEncrypt({default_key_size: 2048});
        encrypt.getKey();
        
        rsaKeys = {
            public: encrypt.getPublicKey(),
            private: encrypt.getPrivateKey()
        };
        
        document.getElementById('publicKey').textContent = rsaKeys.public;
        document.getElementById('publicKeyDisplay').style.display = 'block';
        
        showStatus('senderStatus', 'success', '✅ RSA keys generated successfully!');
    } catch (error) {
        showStatus('senderStatus', 'error', '❌ Error generating keys: ' + error.message);
    }
}

/**
 * Encrypt message using hybrid encryption (AES + RSA)
 */
function encryptMessage() {
    const message = document.getElementById('message').value.trim();
    
    if (!message) {
        showStatus('senderStatus', 'error', '❌ Please enter a message to encrypt');
        return;
    }
    
    if (!rsaKeys) {
        showStatus('senderStatus', 'error', '❌ Please generate RSA keys first');
        return;
    }
    
    try {
        // Generate random AES key and IV
        aesKey = CryptoJS.lib.WordArray.random(256/8);
        iv = CryptoJS.lib.WordArray.random(128/8);
        
        // Encrypt message with AES
        const encrypted = CryptoJS.AES.encrypt(message, aesKey, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        
        // Encrypt AES key with RSA
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(rsaKeys.public);
        const encryptedAESKey = encrypt.encrypt(aesKey.toString());
        
        if (!encryptedAESKey) {
            throw new Error('Failed to encrypt AES key with RSA');
        }
        
        // Store encrypted data
        encryptedData = {
            message: encrypted.toString(),
            key: encryptedAESKey,
            iv: iv.toString()
        };
        
        // Display results
        document.getElementById('encryptedMessage').textContent = encryptedData.message;
        document.getElementById('encryptedAESKey').textContent = encryptedData.key;
        document.getElementById('ivDisplay').textContent = encryptedData.iv;
        document.getElementById('encryptedOutput').style.display = 'block';
        
        showStatus('senderStatus', 'success', '✅ Message encrypted successfully! Share the encrypted data with the recipient.');
        
    } catch (error) {
        showStatus('senderStatus', 'error', '❌ Encryption failed: ' + error.message);
    }
}

/**
 * Auto-fill receiver inputs with sender's encrypted data
 */
function autoFillFromSender() {
    if (!encryptedData.message) {
        showStatus('receiverStatus', 'error', '❌ No encrypted data available. Please encrypt a message first.');
        return;
    }
    
    document.getElementById('encryptedMessageInput').value = encryptedData.message;
    document.getElementById('encryptedKeyInput').value = encryptedData.key;
    document.getElementById('ivInput').value = encryptedData.iv;
    
    showStatus('receiverStatus', 'success', '✅ Data auto-filled from sender');
}

/**
 * Decrypt message using hybrid decryption (RSA + AES)
 */
function decryptMessage() {
    const encryptedMessage = document.getElementById('encryptedMessageInput').value.trim();
    const encryptedKey = document.getElementById('encryptedKeyInput').value.trim();
    const ivStr = document.getElementById('ivInput').value.trim();
    
    if (!encryptedMessage || !encryptedKey || !ivStr) {
        showStatus('receiverStatus', 'error', '❌ Please fill in all encrypted data fields');
        return;
    }
    
    if (!rsaKeys) {
        showStatus('receiverStatus', 'error', '❌ No RSA keys available. Please generate keys first.');
        return;
    }
    
    try {
        // Decrypt AES key with RSA private key
        const decrypt = new JSEncrypt();
        decrypt.setPrivateKey(rsaKeys.private);
        const decryptedAESKey = decrypt.decrypt(encryptedKey);
        
        if (!decryptedAESKey) {
            throw new Error('Failed to decrypt AES key with RSA private key');
        }
        
        // Convert back to WordArray
        const aesKeyWordArray = CryptoJS.enc.Hex.parse(decryptedAESKey);
        const ivWordArray = CryptoJS.enc.Hex.parse(ivStr);
        
        // Decrypt message with AES
        const decrypted = CryptoJS.AES.decrypt(encryptedMessage, aesKeyWordArray, {
            iv: ivWordArray,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        
        const decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
        
        if (!decryptedMessage) {
            throw new Error('Failed to decrypt message - invalid key or corrupted data');
        }
        
        // Display decrypted message
        document.getElementById('decryptedMessage').textContent = decryptedMessage;
        document.getElementById('decryptedOutput').style.display = 'block';
        
        showStatus('receiverStatus', 'success', '✅ Message decrypted successfully!');
        
    } catch (error) {
        showStatus('receiverStatus', 'error', '❌ Decryption failed: ' + error.message);
    }
}

/**
 * Display status messages to user
 * @param {string} elementId - ID of the status element
 * @param {string} type - Type of status (success, error)
 * @param {string} message - Message to display
 */
function showStatus(elementId, type, message) {
    const statusElement = document.getElementById(elementId);
    statusElement.className = `status ${type}`;
    statusElement.textContent = message;
    statusElement.style.display = 'block';
    
    // Auto-hide after 5 seconds for success messages
    if (type === 'success') {
        setTimeout(() => {
            statusElement.style.display = 'none';
        }, 5000);
    }
}

/**
 * Initialize application with sample data
 */
window.onload = function() {
    document.getElementById('message').value = "This is a secret message that will be encrypted using hybrid encryption!";
};