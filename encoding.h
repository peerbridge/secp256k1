#ifndef SECP256K1_ENCODING_H
#define SECP256K1_ENCODING_H

#include <string>
#include <vector>

namespace encoding::hex {
    constexpr inline static char characters[] = "0123456789abcdef";

    std::vector<uint8_t> DecodeString(const std::string& s);

    std::string EncodeToString(const std::vector<uint8_t>& src);
}

#endif //SECP256K1_ENCODING_H
