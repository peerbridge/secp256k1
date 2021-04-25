#include <gtest/gtest.h>
#include "encoding.h"
#include "library.h"

TEST(EncryptionTest, CreateKeyPair) {
    const auto& [privateKey, publicKey] = secp256k1::Encryption::getInstance().createKeyPair();
    EXPECT_TRUE(privateKey);
    EXPECT_TRUE(publicKey);
}

TEST(EncryptionTest, ComputePublicKey) {
    const auto& [privateKey, publicKey] = secp256k1::Encryption::getInstance().createKeyPair();
    const std::unique_ptr<secp256k1::ByteArray> pk = secp256k1::Encryption::getInstance().computePublicKey(*privateKey);
    EXPECT_EQ(publicKey->size(), pk->size());
    for (std::size_t i = 0; i < publicKey->size(); ++i) {
        EXPECT_EQ((*publicKey)[i], (*pk)[i]);
    }
}

TEST(EncryptionTest, Sign) {
    const std::string keyHex = "60f8700baf057e6131b912b97f2e36f54a67544a5f4659de348e988306ab1a3f";
    const secp256k1::ByteArray key = encoding::hex::DecodeString(keyHex);

    const std::string msgHex = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969";
    const secp256k1::ByteArray msg = encoding::hex::DecodeString(msgHex);

    const std::string sigHex = "b97676fd0290f9b98c02e0bf11c495af25fd4126a63e46ec90907c15ae7ff30a727e97bf424f31d067becdcc5a0549441e9a918bbe6defc2dcaea52021bab267";
    const secp256k1::ByteArray sig = encoding::hex::DecodeString(sigHex);

    const std::unique_ptr<secp256k1::ByteArray> signature = secp256k1::Encryption::getInstance().sign(msg, key);
    EXPECT_EQ(sig.size(), signature->size() - 1);
    for (std::size_t i = 0; i < signature->size() - 1; ++i) {
        EXPECT_EQ(sig[i], (*signature)[i]);
    }
}

TEST(EncryptionTest, VerifySignature) {
    const std::string keyHex = "02caa8bded7764cca5bde64c10ae54fc91f4bcd2de08eb4c66b1e2dc3d9dd5519d";
    const secp256k1::ByteArray key = encoding::hex::DecodeString(keyHex);

    const std::string msgHex = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969";
    const secp256k1::ByteArray msg = encoding::hex::DecodeString(msgHex);

    const std::string sigHex = "b97676fd0290f9b98c02e0bf11c495af25fd4126a63e46ec90907c15ae7ff30a727e97bf424f31d067becdcc5a0549441e9a918bbe6defc2dcaea52021bab267";
    const secp256k1::ByteArray sig = encoding::hex::DecodeString(sigHex);

    EXPECT_TRUE(secp256k1::Encryption::getInstance().verifySignature(msg, key, sig));
}

