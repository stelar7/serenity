/*
 * Copyright (c) 2024, stelar7  <dudedbz@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteBuffer.h>
#include <LibCrypto/BigInt/UnsignedBigInteger.h>
#include <LibCrypto/Hash/MGF.h>
#include <LibCrypto/Hash/SHA1.h>
#include <LibCrypto/Hash/SHA2.h>
#include <LibCrypto/PK/RSA.h>
#include <LibCrypto/Padding/OAEP.h>
#include <LibTest/TestCase.h>

// https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf
TEST_CASE(test_oaep)
{
    u8 message_raw[16] {
        0xd4, 0x36, 0xe9, 0x95, 0x69, 0xfd, 0x32, 0xa7, 0xc8, 0xa0, 0x5b, 0xbc, 0x90, 0xd3, 0x2c, 0x49
    };
    auto message = ReadonlyBytes { message_raw, 16 };

    u8 params_raw[0] {};
    auto params = ReadonlyBytes { params_raw, 0 };

    u8 expected_raw[127] {
        0xeb, 0x7a, 0x19, 0xac, 0xe9, 0xe3, 0x00, 0x63,
        0x50, 0xe3, 0x29, 0x50, 0x4b, 0x45, 0xe2, 0xca,
        0x82, 0x31, 0x0b, 0x26, 0xdc, 0xd8, 0x7d, 0x5c,
        0x68, 0xf1, 0xee, 0xa8, 0xf5, 0x52, 0x67, 0xc3,
        0x1b, 0x2e, 0x8b, 0xb4, 0x25, 0x1f, 0x84, 0xd7,
        0xe0, 0xb2, 0xc0, 0x46, 0x26, 0xf5, 0xaf, 0xf9,
        0x3e, 0xdc, 0xfb, 0x25, 0xc9, 0xc2, 0xb3, 0xff,
        0x8a, 0xe1, 0x0e, 0x83, 0x9a, 0x2d, 0xdb, 0x4c,
        0xdc, 0xfe, 0x4f, 0xf4, 0x77, 0x28, 0xb4, 0xa1,
        0xb7, 0xc1, 0x36, 0x2b, 0xaa, 0xd2, 0x9a, 0xb4,
        0x8d, 0x28, 0x69, 0xd5, 0x02, 0x41, 0x21, 0x43,
        0x58, 0x11, 0x59, 0x1b, 0xe3, 0x92, 0xf9, 0x82,
        0xfb, 0x3e, 0x87, 0xd0, 0x95, 0xae, 0xb4, 0x04,
        0x48, 0xdb, 0x97, 0x2f, 0x3a, 0xc1, 0x4f, 0x7b,
        0xc2, 0x75, 0x19, 0x52, 0x81, 0xce, 0x32, 0xd2,
        0xf1, 0xb7, 0x6d, 0x4d, 0x35, 0x3e, 0x2d
    };
    auto expected = ReadonlyBytes { expected_raw, 127 };

    u8 seed_data[20] {
        0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34,
        0x89, 0xb4, 0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2,
        0xf0, 0x6c, 0xb5, 0x8f
    };

    auto maybe_result = Crypto::Padding::OAEP::encode<Crypto::Hash::SHA1, Crypto::Hash::MGF>(
        message,
        params,
        127,
        [&](auto buffer) {
            memcpy(buffer.data(), seed_data, 20);
        });
    auto result = maybe_result.release_value();

    EXPECT_EQ(expected, result);

    auto maybe_decode = Crypto::Padding::OAEP::decode<Crypto::Hash::SHA1, Crypto::Hash::MGF>(result, params);
    auto decoded = maybe_decode.release_value();

    EXPECT_EQ(message, decoded);

    /*
        u8 n_bytes[128] {
            0xbb, 0xf8, 0x2f, 0x09, 0x06, 0x82, 0xce, 0x9c, 0x23, 0x38, 0xac, 0x2b, 0x9d, 0xa8, 0x71, 0xf7,
            0x36, 0x8d, 0x07, 0xee, 0xd4, 0x10, 0x43, 0xa4, 0x40, 0xd6, 0xb6, 0xf0, 0x74, 0x54, 0xf5, 0x1f,
            0xb8, 0xdf, 0xba, 0xaf, 0x03, 0x5c, 0x02, 0xab, 0x61, 0xea, 0x48, 0xce, 0xeb, 0x6f, 0xcd, 0x48,
            0x76, 0xed, 0x52, 0x0d, 0x60, 0xe1, 0xec, 0x46, 0x19, 0x71, 0x9d, 0x8a, 0x5b, 0x8b, 0x80, 0x7f,
            0xaf, 0xb8, 0xe0, 0xa3, 0xdf, 0xc7, 0x37, 0x72, 0x3e, 0xe6, 0xb4, 0xb7, 0xd9, 0x3a, 0x25, 0x84,
            0xee, 0x6a, 0x64, 0x9d, 0x06, 0x09, 0x53, 0x74, 0x88, 0x34, 0xb2, 0x45, 0x45, 0x98, 0x39, 0x4e,
            0xe0, 0xaa, 0xb1, 0x2d, 0x7b, 0x61, 0xa5, 0x1f, 0x52, 0x7a, 0x9a, 0x41, 0xf6, 0xc1, 0x68, 0x7f,
            0xe2, 0x53, 0x72, 0x98, 0xca, 0x2a, 0x8f, 0x59, 0x46, 0xf8, 0xe5, 0xfd, 0x09, 0x1d, 0xbd, 0xcb
        };

        u8 e_bytes[1] { 0x11 };

        u8 p_bytes[64] {
            0xee, 0xcf, 0xae, 0x81, 0xb1, 0xb9, 0xb3, 0xc9, 0x08, 0x81, 0x0b, 0x10, 0xa1, 0xb5, 0x60, 0x01,
            0x99, 0xeb, 0x9f, 0x44, 0xae, 0xf4, 0xfd, 0xa4, 0x93, 0xb8, 0x1a, 0x9e, 0x3d, 0x84, 0xf6, 0x32,
            0x12, 0x4e, 0xf0, 0x23, 0x6e, 0x5d, 0x1e, 0x3b, 0x7e, 0x28, 0xfa, 0xe7, 0xaa, 0x04, 0x0a, 0x2d,
            0x5b, 0x25, 0x21, 0x76, 0x45, 0x9d, 0x1f, 0x39, 0x75, 0x41, 0xba, 0x2a, 0x58, 0xfb, 0x65, 0x99
        };

        u8 q_bytes[64] {
            0xc9, 0x7f, 0xb1, 0xf0, 0x27, 0xf4, 0x53, 0xf6, 0x34, 0x12, 0x33, 0xea, 0xaa, 0xd1, 0xd9, 0x35,
            0x3f, 0x6c, 0x42, 0xd0, 0x88, 0x66, 0xb1, 0xd0, 0x5a, 0x0f, 0x20, 0x35, 0x02, 0x8b, 0x9d, 0x86,
            0x98, 0x40, 0xb4, 0x16, 0x66, 0xb4, 0x2e, 0x92, 0xea, 0x0d, 0xa3, 0xb4, 0x32, 0x04, 0xb5, 0xcf,
            0xce, 0x33, 0x52, 0x52, 0x4d, 0x04, 0x16, 0xa5, 0xa4, 0x41, 0xe7, 0x00, 0xaf, 0x46, 0x15, 0x03
        };

        u8 dp_bytes[64] {
            0x54, 0x49, 0x4c, 0xa6, 0x3e, 0xba, 0x03, 0x37, 0xe4, 0xe2, 0x40, 0x23, 0xfc, 0xd6, 0x9a, 0x5a,
            0xeb, 0x07, 0xdd, 0xdc, 0x01, 0x83, 0xa4, 0xd0, 0xac, 0x9b, 0x54, 0xb0, 0x51, 0xf2, 0xb1, 0x3e,
            0xd9, 0x49, 0x09, 0x75, 0xea, 0xb7, 0x74, 0x14, 0xff, 0x59, 0xc1, 0xf7, 0x69, 0x2e, 0x9a, 0x2e,
            0x20, 0x2b, 0x38, 0xfc, 0x91, 0x0a, 0x47, 0x41, 0x74, 0xad, 0xc9, 0x3c, 0x1f, 0x67, 0xc9, 0x81
        };

        u8 dq_bytes[64] {
            0x47, 0x1e, 0x02, 0x90, 0xff, 0x0a, 0xf0, 0x75, 0x03, 0x51, 0xb7, 0xf8, 0x78, 0x86, 0x4c, 0xa9,
            0x61, 0xad, 0xbd, 0x3a, 0x8a, 0x7e, 0x99, 0x1c, 0x5c, 0x05, 0x56, 0xa9, 0x4c, 0x31, 0x46, 0xa7,
            0xf9, 0x80, 0x3f, 0x8f, 0x6f, 0x8a, 0xe3, 0x42, 0xe9, 0x31, 0xfd, 0x8a, 0xe4, 0x7a, 0x22, 0x0d,
            0x1b, 0x99, 0xa4, 0x95, 0x84, 0x98, 0x07, 0xfe, 0x39, 0xf9, 0x24, 0x5a, 0x98, 0x36, 0xda, 0x3d
        };

        u8 qinv_bytes[64] {
            0xb0, 0x6c, 0x4f, 0xda, 0xbb, 0x63, 0x01, 0x19, 0x8d, 0x26, 0x5b, 0xdb, 0xae, 0x94, 0x23, 0xb3,
            0x80, 0xf2, 0x71, 0xf7, 0x34, 0x53, 0x88, 0x50, 0x93, 0x07, 0x7f, 0xcd, 0x39, 0xe2, 0x11, 0x9f,
            0xc9, 0x86, 0x32, 0x15, 0x4f, 0x58, 0x83, 0xb1, 0x67, 0xa9, 0x67, 0xbf, 0x40, 0x2b, 0x4e, 0x9e,
            0x2e, 0x0f, 0x96, 0x56, 0xe6, 0x98, 0xea, 0x36, 0x66, 0xed, 0xfb, 0x25, 0x79, 0x80, 0x39, 0xf7
        };

        u8 expected_rsa_value_bytes[128] {
            0x12, 0x53, 0xe0, 0x4d, 0xc0, 0xa5, 0x39, 0x7b, 0xb4, 0x4a, 0x7a, 0xb8, 0x7e, 0x9b, 0xf2, 0xa0,
            0x39, 0xa3, 0x3d, 0x1e, 0x99, 0x6f, 0xc8, 0x2a, 0x94, 0xcc, 0xd3, 0x00, 0x74, 0xc9, 0x5d, 0xf7,
            0x63, 0x72, 0x20, 0x17, 0x06, 0x9e, 0x52, 0x68, 0xda, 0x5d, 0x1c, 0x0b, 0x4f, 0x87, 0x2c, 0xf6,
            0x53, 0xc1, 0x1d, 0xf8, 0x23, 0x14, 0xa6, 0x79, 0x68, 0xdf, 0xea, 0xe2, 0x8d, 0xef, 0x04, 0xbb,
            0x6d, 0x84, 0xb1, 0xc3, 0x1d, 0x65, 0x4a, 0x19, 0x70, 0xe5, 0x78, 0x3b, 0xd6, 0xeb, 0x96, 0xa0,
            0x24, 0xc2, 0xca, 0x2f, 0x4a, 0x90, 0xfe, 0x9f, 0x2e, 0xf5, 0xc9, 0xc1, 0x40, 0xe5, 0xbb, 0x48,
            0xda, 0x95, 0x36, 0xad, 0x87, 0x00, 0xc8, 0x4f, 0xc9, 0x13, 0x0a, 0xde, 0xa7, 0x4e, 0x55, 0x8d,
            0x51, 0xa7, 0x4d, 0xdf, 0x85, 0xd8, 0xb5, 0x0d, 0xe9, 0x68, 0x38, 0xd6, 0x06, 0x3e, 0x09, 0x55
        };
    */

    u8 n_bytes[128] {
        0xb0, 0x3f, 0x18, 0x0f, 0xda, 0xa0, 0x62, 0x27, 0x5e, 0x55, 0xeb, 0x8e, 0xe8, 0x6d, 0x62, 0xbf,
        0x50, 0xf5, 0xf2, 0xfe, 0x89, 0x83, 0xff, 0xfb, 0x7a, 0x6f, 0x46, 0x9a, 0xf1, 0x98, 0xb3, 0x77,
        0x73, 0x9a, 0x03, 0x91, 0xb1, 0xe9, 0xa8, 0x5c, 0x26, 0x36, 0x07, 0x71, 0x14, 0x6e, 0xe8, 0xa5,
        0x0b, 0x56, 0x18, 0xe3, 0xf3, 0x68, 0xc3, 0x90, 0x5a, 0x37, 0xfd, 0x0e, 0xf9, 0x9e, 0x2c, 0x78,
        0x5a, 0xff, 0x12, 0x43, 0xfa, 0xd8, 0x9f, 0x76, 0x60, 0xc7, 0xd4, 0xc5, 0x8b, 0x28, 0xb1, 0xbc,
        0x77, 0xb8, 0x37, 0x4d, 0xe8, 0x1e, 0x2a, 0xdb, 0xd8, 0xdf, 0xaf, 0xc7, 0xcb, 0x1a, 0x0c, 0x5c,
        0x46, 0x8b, 0x7f, 0x75, 0x58, 0xf7, 0x70, 0xfe, 0x40, 0x0d, 0xfe, 0x87, 0xd5, 0x19, 0x22, 0xe0,
        0x20, 0x0d, 0x78, 0x85, 0x2e, 0x27, 0x8e, 0x88, 0xe2, 0x01, 0x28, 0xa8, 0x63, 0x17, 0xb1, 0x05
    };

    u8 e_bytes[3] { 0x01, 0x00, 0x01 };

    u8 d_bytes[128] {
        0x0b, 0x21, 0x37, 0x89, 0x31, 0x6e, 0x9d, 0x36, 0xd7, 0x10, 0x4e, 0x1e, 0x0f, 0x43, 0x9b, 0x1a,
        0x5c, 0x47, 0xe5, 0x26, 0xae, 0xf3, 0x46, 0x41, 0x70, 0xa4, 0xf6, 0xc7, 0x36, 0xed, 0xae, 0xf0,
        0x4d, 0x3d, 0x4d, 0xaf, 0x90, 0x15, 0xe2, 0x8d, 0xcb, 0xd4, 0x45, 0x1f, 0x89, 0x0c, 0x0b, 0x9b,
        0xcd, 0x38, 0x61, 0xbd, 0x81, 0x63, 0xf2, 0xac, 0xf0, 0x0e, 0xe6, 0xe7, 0x8b, 0x70, 0x07, 0x91,
        0x9e, 0x13, 0xe7, 0x2c, 0xca, 0x37, 0x96, 0x05, 0x9a, 0x82, 0x21, 0xdb, 0x92, 0x3c, 0xc8, 0x20,
        0x75, 0xfd, 0x5e, 0x6c, 0x31, 0x71, 0x6b, 0xcf, 0x69, 0xd9, 0x8a, 0x27, 0xa8, 0xb1, 0xbb, 0x31,
        0x99, 0x93, 0x18, 0x9f, 0xaa, 0x50, 0x3d, 0xc1, 0xcd, 0x0b, 0x30, 0xa4, 0x7f, 0xcb, 0x64, 0x94,
        0x05, 0x66, 0xc1, 0xd9, 0x9e, 0xd6, 0x74, 0x1b, 0xae, 0x8c, 0x76, 0xb7, 0xe7, 0x8e, 0x0e, 0x81
    };

    u8 p_bytes[64] {
        0xf2, 0x53, 0x10, 0xb0, 0xac, 0x07, 0xbc, 0x01, 0x0a, 0xb0, 0x67, 0xfb, 0xe6, 0xf7, 0xfa, 0xc9,
        0x1e, 0x6f, 0xad, 0x61, 0xe8, 0xf0, 0xc7, 0x4f, 0x42, 0x28, 0xdd, 0x04, 0x28, 0x9e, 0xe1, 0xff,
        0xb8, 0xaf, 0xb0, 0x64, 0x94, 0x6f, 0x94, 0xc6, 0xb0, 0x44, 0x94, 0x45, 0x1a, 0xb0, 0xc6, 0x2a,
        0xae, 0x6f, 0xd4, 0x3d, 0xba, 0x2e, 0x3b, 0x8d, 0x39, 0x97, 0xf6, 0x51, 0x2e, 0x76, 0x04, 0x81
    };

    u8 q_bytes[64] {
        0xba, 0x31, 0x61, 0x3a, 0xf8, 0xf9, 0xff, 0x8e, 0x30, 0xca, 0xeb, 0xe0, 0x25, 0x70, 0x68, 0xef,
        0x1a, 0xb7, 0x1e, 0x5a, 0xa0, 0x39, 0x9a, 0xfb, 0xb3, 0x1a, 0xae, 0x41, 0x9e, 0xeb, 0xbb, 0x3b,
        0x06, 0xcc, 0x21, 0x9e, 0x35, 0x19, 0xc1, 0x76, 0x18, 0x8a, 0xec, 0x44, 0x5c, 0x66, 0xf2, 0x82,
        0xcb, 0x68, 0xdf, 0x5d, 0x7c, 0xfd, 0x7a, 0x21, 0x4d, 0xb5, 0x99, 0x64, 0x61, 0x32, 0x5a, 0x85
    };

    u8 dp_bytes[64] {
        0xbb, 0xde, 0x0c, 0x4d, 0x7c, 0x41, 0xce, 0xce, 0xdb, 0xf3, 0xa1, 0xda, 0x58, 0xd9, 0x9e, 0x53,
        0x78, 0x46, 0x4a, 0x9c, 0x62, 0xd4, 0xf1, 0x20, 0x90, 0x81, 0x4f, 0xc0, 0x5e, 0xa1, 0xb7, 0x42,
        0xe3, 0x73, 0x4a, 0x04, 0xe0, 0x53, 0x95, 0x7b, 0x68, 0xc2, 0xf2, 0x54, 0x94, 0xf9, 0xc1, 0xd8,
        0xeb, 0x3e, 0x05, 0xc5, 0x09, 0x67, 0xb8, 0x81, 0xa7, 0xca, 0x19, 0x8c, 0x1c, 0xc2, 0x20, 0x81
    };

    u8 dq_bytes[64] {
        0x67, 0xf8, 0x73, 0x06, 0xef, 0x49, 0x0a, 0xbf, 0x67, 0xd7, 0xa8, 0x67, 0x7e, 0x00, 0x8b, 0x58,
        0x19, 0x5e, 0xf0, 0x00, 0x43, 0x40, 0x67, 0x9e, 0xed, 0xa0, 0x94, 0x75, 0xe8, 0x3c, 0x52, 0x4c,
        0xdf, 0xba, 0xd5, 0x7a, 0xf6, 0xc3, 0xef, 0x17, 0xf7, 0x14, 0x7c, 0x62, 0xa0, 0x06, 0x8c, 0x9d,
        0x24, 0xe0, 0xe6, 0xf9, 0xd9, 0x75, 0xe1, 0xe0, 0xfe, 0xf7, 0xcd, 0x34, 0x14, 0x62, 0x7d, 0xd1
    };

    u8 qinv_bytes[64] {
        0x16, 0x8e, 0x7b, 0x5f, 0x6c, 0x3c, 0x6d, 0x9e, 0xd0, 0x09, 0x30, 0xec, 0x5e, 0x17, 0x9f, 0x2a,
        0xd4, 0xe2, 0x3b, 0x3f, 0x20, 0xa1, 0x16, 0x66, 0x68, 0x91, 0x8a, 0xfe, 0x64, 0x30, 0xe5, 0x23,
        0xb4, 0x66, 0x20, 0xcd, 0xc8, 0x18, 0x98, 0x8a, 0xed, 0xe6, 0x18, 0xd6, 0x69, 0xca, 0xcf, 0xa7,
        0xbf, 0x70, 0x4f, 0x39, 0xb0, 0xcb, 0xd1, 0xe7, 0xe9, 0xab, 0x73, 0x9e, 0x4c, 0x8b, 0x5a, 0xbd
    };

    // auto expected_rsa_value = ReadonlyBytes { expected_rsa_value_bytes, 128 };

    auto d = Crypto::UnsignedBigInteger::import_data(d_bytes, sizeof(d_bytes));
    auto n = Crypto::UnsignedBigInteger::import_data(n_bytes, sizeof(n_bytes));
    auto e = Crypto::UnsignedBigInteger::import_data(e_bytes, sizeof(e_bytes));
    auto p = Crypto::UnsignedBigInteger::import_data(p_bytes, sizeof(p_bytes));
    auto q = Crypto::UnsignedBigInteger::import_data(q_bytes, sizeof(q_bytes));
    auto dp = Crypto::UnsignedBigInteger::import_data(dp_bytes, sizeof(dp_bytes));
    auto dq = Crypto::UnsignedBigInteger::import_data(dq_bytes, sizeof(dq_bytes));
    auto qinv = Crypto::UnsignedBigInteger::import_data(qinv_bytes, sizeof(qinv_bytes));
    // auto private_key = Crypto::PK::RSAPrivateKey<>::from_crt(n, e, p, q, dp, dq, qinv);
    auto private_key = Crypto::PK::RSAPrivateKey(n, d, e, p, q, dp, dq, qinv);
    auto public_key = Crypto::PK::RSAPublicKey(n, e);
    auto rsa = Crypto::PK::RSA(public_key, private_key);

    auto maybe_encode_buffer = ByteBuffer::create_zeroed(128);
    auto encode_buffer = maybe_encode_buffer.release_value();
    auto encode_span = encode_buffer.bytes();

    rsa.encrypt(result, encode_span);
    // EXPECT_EQ(expected_rsa_value, encode_span);

    auto maybe_decode_buffer = ByteBuffer::create_zeroed(128);
    auto decode_buffer = maybe_decode_buffer.release_value();
    auto decode_span = decode_buffer.bytes();
    rsa.decrypt(encode_span, decode_span);

    dbgln("Before Encode: {:hex-dump}", result.span());
    dbgln("Before Decode: {:hex-dump}", encode_span);
    dbgln("After Decode: {:hex-dump}", decode_span);

    EXPECT_EQ(decode_span, result);
}
