#include "encoding.h"

std::vector<uint8_t> encoding::hex::DecodeString(const std::string& s) {
    std::vector<uint8_t> b(s.size()/2, 0);

    for (std::size_t i = 0; i < s.size(); i += 2) {
        std::string&& sub = s.substr(i, 2);
        b[i / 2] = std::strtoul(sub.c_str(), nullptr, 16);
    }

    return b;
}

std::string encoding::hex::EncodeToString(const std::vector<uint8_t>& src) {
    std::string s(src.size() * 2, 0);

    uint8_t&& i = 0;
    for (const auto &byte : src) {
        s[i++] = encoding::hex::characters[byte >> 4 & 0x0f];
        s[i++] = encoding::hex::characters[byte & 0x0f];
    }

    return s;
}
