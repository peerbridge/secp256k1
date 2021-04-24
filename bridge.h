#ifndef SECP256K1_BRIDGE_H
#define SECP256K1_BRIDGE_H

#include "library.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Container for a Keypair.
 */
typedef struct {
    const unsigned char *privateKey;
    const unsigned char *publicKey;
} KeyPair;

/**
 * Generate a new random ECDSA key pair as a pair of private and public key.
 *
 * @return a new random ECDSA key pair in the form [private, public]
 */
static KeyPair createKeyPair();

/**
 * Compute the public key from a private key
 *
 * @param key - the private key to compute the public key for
 * @param length - the length of the resulting public key
 * @return the public key encoded according to the given length
 */
static const unsigned char* computePublicKey(const secp256k1::ByteArray &key, const secp256k1::PublicKeyLength &length = secp256k1::PublicKeyLength::Compressed);

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
static const unsigned char* sign(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key);

/**
 * Check that the given public key created the signature over the message
 *
 * @param msg - the message the signature was build upon
 * @param key - the public key of the signer
 * @param sig - the produced signature to verify, without the recovery id (compact format, 64-Bytes)
 * @return a Boolean indicating if the signature over the message was created using the public key
 */
static bool verifySignature(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &key, const secp256k1::ByteArray &sig);

/**
 * Encode a public key according to the specified length.
 * This method can be used to convert between public key formats.
 * The input/output formats are chosen depending on the length of the input/output buffers.
 *
 * @param key - the public key to encode
 * @param length - the length of the resulting public key
 * @return the public key encoded according to the given length
 */
static const unsigned char* encodePublicKey(const secp256k1::ByteArray &key, const secp256k1::PublicKeyLength &length);

/**
 * Encode the given public key into a 33-byte compressed format.
 *
 * @param key - the public key to format
 * @return the public key in compressed format (33-Byte)
 */
static const unsigned char* compressPublicKey(const secp256k1::ByteArray &key);

/**
 * Parses a public key in the 33-byte compressed format and encode it into a 65-byte uncompressed format.
 *
 * @param key - the public key to format
 * @return the public key in uncompressed format (65-Byte)
 */
static const unsigned char* decompressPublicKey(const secp256k1::ByteArray &key);

/**
 * Recover the public key of an encoded compact signature.
 *
 * @param msg - the message the signature was created on
 * @param sig - the signature in order to recover the public key
 * @param length - the length of the resulting public key
 * @return the public key encoded according to the given length
 */
static const unsigned char* recoverPublicKey(const secp256k1::ByteArray &msg, const secp256k1::ByteArray &sig, const secp256k1::PublicKeyLength &length = secp256k1::PublicKeyLength::Compressed);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif //SECP256K1_BRIDGE_H
