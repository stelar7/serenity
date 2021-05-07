/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Span.h>
#include <AK/Vector.h>
#include <LibCrypto/BigInt/SignedBigInteger.h>
#include <LibCrypto/BigInt/UnsignedBigInteger.h>
#include <LibCrypto/NumberTheory/ModularFunctions.h>
#include <LibCrypto/PK/PK.h>

namespace Crypto {
namespace PK {
struct EllipticCurvePoint {
    EllipticCurvePoint(SignedBigInteger x, SignedBigInteger y)
        : x(x)
        , y(y) {};

    SignedBigInteger x;
    SignedBigInteger y;

    EllipticCurvePoint negate();
    EllipticCurvePoint add(EllipticCurvePoint other, UnsignedBigInteger n);
    EllipticCurvePoint twice(UnsignedBigInteger n, UnsignedBigInteger a);
    EllipticCurvePoint multiply(UnsignedBigInteger n, UnsignedBigInteger a, UnsignedBigInteger scalar);
};

class EllipticCurveDomain {
public:
    EllipticCurveDomain(
        UnsignedBigInteger p,
        SignedBigInteger a,
        SignedBigInteger b,
        SignedBigInteger Gx,
        SignedBigInteger Gy)
        : p(p)
        , a(a)
        , b(b)
        , G({ Gx, Gy }) {};

private:
    // Prime
    UnsignedBigInteger p;

    // Equation parameters
    SignedBigInteger a;
    SignedBigInteger b;

    // Base point
    EllipticCurvePoint G;

    // Point order
    UnsignedBigInteger n;

    // Cofactor
    UnsignedBigInteger h;
};

class P192 : EllipticCurveDomain {
    P192()
        : EllipticCurveDomain(
            UnsignedBigInteger::from_base10("6277101735386680763835789423207666416083908700390324961279"),
            SignedBigInteger::from_base10("-3"),
            SignedBigInteger::from_base10("2455155546008943817740293915197451784769108058161191238065"),
            SignedBigInteger::from_base10("602046282375688656758213480587526111916698976636884684818"),
            SignedBigInteger::from_base10("174050332293622031404857552280219410364023488927386650641")) {};
};

}
}
