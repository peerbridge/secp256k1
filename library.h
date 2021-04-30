#ifndef SECP256K1_LIBRARY_H
#define SECP256K1_LIBRARY_H

#include <climits>
#include <memory>
#include <random>
#include <utility>
#include <vector>
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"

namespace secp256k1 {
    typedef std::vector<unsigned char> ByteArray;

    /**
     * Number of Bytes in a ECDSA private key.
     */
    constexpr inline static int8_t PrivateKeyLength = 32;

    /**
     * Number of Bytes in a ECDH secret.
     */
    constexpr inline static int8_t SecretLength = 32;

    /**
     * Number of Bytes in a ECDSA signature (excluding a recovery ID)
     */
    constexpr inline static int8_t SignatureLength = 64;

    /**
     * Number of Bytes in a message, to compute the signature for
     */
    constexpr inline static int8_t MessageLength = 32;

    /**
     * Number of Bytes of a key, 33 for compressed keys, 65 for uncompressed keys
     */
    enum PublicKeyLength {
        Compressed = 33,
        Uncompressed = 65,
    };

    class Encryption final {
    public:
        Encryption(Encryption const&) = delete;
        void operator=(Encryption const&) = delete;

        /**
         * Get the instance of the Encryption class.
         *
         * @return the singleton instance
         */
        static Encryption& getInstance()
        {
            // Guaranteed to be destroyed.
            // Instantiated on first use.
            // Thread-safe
            static Encryption instance;

            return instance;
        }

        /**
         * Generate a new random ECDSA key pair as a pair of private and public key.
         *
         * @return a new random ECDSA key pair in the form [private, public]
         */
        std::pair<std::unique_ptr<ByteArray>, std::unique_ptr<ByteArray>> createKeyPair();

        /**
         * Compute the public key from a private key
         *
         * @param key - the private key to compute the public key for
         * @param length - the length of the resulting public key
         * @return the public key encoded according to the given length
         */
        std::unique_ptr<ByteArray> computePublicKey(const secp256k1::ByteArray &key, const PublicKeyLength &length = PublicKeyLength::Compressed);

        /**
         * Compute an EC Diffie-Hellman secret in constant time
         *
         * @param privateKey - the private key, which is used as a 32-byte scalar with which to multiply the point
         * @param publicKey - the public key, to compute the secret with
         * @return a 32-byte vector containing the ECDH secret computed from the point and scalar
         */
        std::unique_ptr<secp256k1::ByteArray> computeSecret(const secp256k1::ByteArray &privateKey, const secp256k1::ByteArray &publicKey);

        /**
         * Sign creates a recoverable ECDSA signature.
         * The produced signature is in the 65-byte [R || S || V] format where V is 0 or 1.
         *
         * The caller is responsible for ensuring that msg cannot be chosen
         * directly by an attacker. It is usually preferable to use a cryptographic
         * hash function on any input before handing it to this function.
         *
         * @param msg - message data to sign with a private key
         * @param key - private key to create the signature with
         * @return the signature of the message using the private key
         */
        std::unique_ptr<ByteArray> sign(const ByteArray &msg, const ByteArray &key);

        /**
         * Check that the given public key created the signature over the message
         *
         * @param msg - the message the signature was build upon
         * @param key - the public key of the signer
         * @param sig - the produced signature to verify, without the recovery id (compact format, 64-Bytes)
         * @return a Boolean indicating if the signature over the message was created using the public key
         */
        bool verifySignature(const ByteArray &msg, const ByteArray &key, const ByteArray &sig);

        /**
         * Encode a public key according to the specified length.
         * This method can be used to convert between public key formats.
         * The input/output formats are chosen depending on the length of the input/output buffers.
         *
         * @param key - the public key to encode
         * @param length - the length of the resulting public key
         * @return the public key encoded according to the given length
         */
        std::unique_ptr<ByteArray> encodePublicKey(const secp256k1::ByteArray &key, const PublicKeyLength &length);

        /**
         * Encode the given public key into a 33-byte compressed format.
         *
         * @param key - the public key to format
         * @return the public key in compressed format (33-Byte)
         */
        std::unique_ptr<ByteArray> compressPublicKey(const secp256k1::ByteArray &key) { return encodePublicKey(key, PublicKeyLength::Compressed); }

        /**
         * Parses a public key in the 33-byte compressed format and encode it into a 65-byte uncompressed format.
         *
         * @param key - the public key to format
         * @return the public key in uncompressed format (65-Byte)
         */
        std::unique_ptr<ByteArray> decompressPublicKey(const secp256k1::ByteArray &key) { return encodePublicKey(key, PublicKeyLength::Uncompressed); }

        /**
         * Recover the public key of an encoded compact signature.
         *
         * @param msg - the message the signature was created on
         * @param sig - the signature in order to recover the public key
         * @param length - the length of the resulting public key
         * @return the public key encoded according to the given length
         */
        std::unique_ptr<ByteArray> recoverPublicKey(const ByteArray &msg, const ByteArray &sig, const PublicKeyLength &length = PublicKeyLength::Compressed);
    private:
        Encryption();
        ~Encryption();

        // a context for signing and signature verification.
        secp256k1_context* ctx;
    };

}

#endif //SECP256K1_LIBRARY_H
