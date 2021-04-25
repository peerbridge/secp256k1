#include <gtest/gtest.h>
#include "encoding.h"

TEST(EncodingHexTest, DecodeString) {
    std::vector<uint8_t> bytes = encoding::hex::DecodeString("48656c6c6f");
    std::string s(bytes.begin(), bytes.end());
    EXPECT_STREQ("Hello", s.data());
}

TEST(EncodingHexTest, EncodeToString) {
    std::string msg = "Hello";
    std::vector<uint8_t> bytes(msg.begin(), msg.end());
    EXPECT_STREQ("48656c6c6f", encoding::hex::EncodeToString(bytes).data());
}
