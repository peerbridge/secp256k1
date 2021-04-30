#include "bridge.h"

KeyPair createKeyPair() {
    const auto& [privateKey, publicKey] = secp256k1::Encryption::getInstance().createKeyPair();
    KeyPair kp;
    kp.privateKey = privateKey.get()->data();
    kp.publicKey = publicKey.get()->data();
    return kp;
}


const unsigned char* computePublicKey(const secp256k1::ByteArray &key, const secp256k1::PublicKeyLength &length) {
    return secp256k1::Encryption::getInstance().computePublicKey(key, length)->data();
}

const unsigned char* computeSecret(const secp256k1::ByteArray &privateKey, const secp256k1::ByteArray &publicKey) {
    return secp256k1::Encryption::getInstance().computeSecret(privateKey, publicKey)->data();
}

const unsigned char* sign(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key) {
    return secp256k1::Encryption::getInstance().sign(msg, key)->data();
}

bool verifySignature(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key, const secp256k1::ByteArray &sig) {
    return secp256k1::Encryption::getInstance().verifySignature(msg, key, sig);
}

const unsigned char* encodePublicKey(const secp256k1::ByteArray &key, const secp256k1::PublicKeyLength &length) {
    return secp256k1::Encryption::getInstance().encodePublicKey(key, length)->data();
}

const unsigned char* compressPublicKey(const secp256k1::ByteArray &key) {
    return encodePublicKey(key, secp256k1::PublicKeyLength::Compressed);
}

const unsigned char* decompressPublicKey(const secp256k1::ByteArray &key) {
    return encodePublicKey(key, secp256k1::PublicKeyLength::Uncompressed);
}

const unsigned char* recoverPublicKey(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &sig, const secp256k1::PublicKeyLength &length) {
    return secp256k1::Encryption::getInstance().recoverPublicKey(msg, sig, length)->data();
}
