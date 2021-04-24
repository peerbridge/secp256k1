#include "library.h"

#pragma ide diagnostic ignored "Simplify"
secp256k1::Encryption::Encryption() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

secp256k1::Encryption::~Encryption() {
    secp256k1_context_destroy(secp256k1::Encryption::ctx);
}

std::pair<std::unique_ptr<secp256k1::ByteArray>, std::unique_ptr<secp256k1::ByteArray>> secp256k1::Encryption::createKeyPair() {
    secp256k1::ByteArray privateKey(secp256k1::PrivateKeyLength);

    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> uniformDist(0, UCHAR_MAX);
    std::generate(privateKey.begin(), privateKey.end(), [&uniformDist, &engine] () { return uniformDist(engine); });

    if (!secp256k1_context_randomize(ctx, privateKey.data())) return std::make_pair(nullptr, nullptr);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, privateKey.data())) return std::make_pair(nullptr, nullptr);

    auto&& len = size_t(secp256k1::PublicKeyLength::Compressed);
    secp256k1::ByteArray publicKey(len);
    uint32_t&& flag = SECP256K1_EC_COMPRESSED;
    if (!secp256k1_ec_pubkey_serialize(ctx, publicKey.data(), &len, &pk, flag)) return std::make_pair(nullptr, nullptr);

    return std::make_pair(std::make_unique<secp256k1::ByteArray>(privateKey), std::make_unique<secp256k1::ByteArray>(publicKey));
}

std::unique_ptr<secp256k1::ByteArray> secp256k1::Encryption::computePublicKey(const secp256k1::ByteArray &key, const secp256k1::PublicKeyLength &length) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, key.data())) return nullptr;

    auto&& len = size_t(length);
    secp256k1::ByteArray out(len);
    uint32_t&& flag = (length == PublicKeyLength::Compressed) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, flag)) return nullptr;

    return std::make_unique<secp256k1::ByteArray>(out);
}

std::unique_ptr<secp256k1::ByteArray> secp256k1::Encryption::sign(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key) {
    if (msg.size() != secp256k1::MessageLength) return nullptr;
    if (key.size() != secp256k1::PrivateKeyLength) return nullptr;

    if (!secp256k1_ec_seckey_verify(ctx, key.data())) return nullptr;

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg.data(), key.data(), secp256k1_nonce_function_rfc6979, nullptr)) return nullptr;

    int32_t recoveryID;
    secp256k1::ByteArray signature(secp256k1::SignatureLength + 1); // 64 bytes Signature + recovery id
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature.data(), &recoveryID, &sig);
    signature[64] = (unsigned char)recoveryID; // add back recovery id to get 65 bytes

    return std::make_unique<secp256k1::ByteArray>(signature);
}

bool secp256k1::Encryption::verifySignature(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key, const secp256k1::ByteArray &sig) {
    if (msg.size() != secp256k1::MessageLength || sig.size() != secp256k1::SignatureLength || key.empty()) return false;

    secp256k1_ecdsa_signature s;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &s, sig.data())) return false;

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, key.data(), key.size())) return false;

    return secp256k1_ecdsa_verify(ctx, &s, msg.data(), &pk) == 1;
}

std::unique_ptr<secp256k1::ByteArray> secp256k1::Encryption::encodePublicKey(const secp256k1::ByteArray &key, const PublicKeyLength &length) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, key.data(), key.size())) return nullptr;

    auto&& len = size_t(length);
    secp256k1::ByteArray out(len);
    uint32_t&& flag = (length == PublicKeyLength::Compressed) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, flag)) return nullptr;

    return std::make_unique<secp256k1::ByteArray>(out);
}

std::unique_ptr<secp256k1::ByteArray> secp256k1::Encryption::recoverPublicKey(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &sig, const PublicKeyLength &length) {
    if (msg.size() != secp256k1::MessageLength) return nullptr;
    if (sig.size() != secp256k1::SignatureLength + 1 || sig[64] >= 4) return nullptr;

    secp256k1_ecdsa_recoverable_signature s;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &s, sig.data(), sig[64])) return nullptr;

    secp256k1_pubkey pk;
    if (!secp256k1_ecdsa_recover(ctx, &pk, &s, msg.data())) return nullptr;

    auto&& len = size_t(length);
    secp256k1::ByteArray out(len);
    uint32_t&& flag = (length == PublicKeyLength::Compressed) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, flag)) return nullptr;

    return std::make_unique<secp256k1::ByteArray>(out);
}
