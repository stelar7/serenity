/*
 * Copyright (c) 2021, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/PK/ECDSA.h>

namespace Crypto {
namespace PK {

EllipticCurvePoint EllipticCurvePoint::negate()
{
    EllipticCurvePoint negated { x, y };
    negated.y.negate();

    return negated;
}

EllipticCurvePoint EllipticCurvePoint::add(EllipticCurvePoint other, UnsignedBigInteger n)
{
    auto a = other.x.minus(x);
    auto b = other.y.minus(y);

    // TODO
    //b = b.mod_inverse(n);
    a = a.multiplied_by(b).divided_by(n).remainder;
    b = a.multiplied_by(a);
    b = ((a.minus(x)).minus(other.x)).divided_by(n).remainder;

    auto new_x = b;
    auto new_y = (a.multiplied_by(x.minus(b))).minus(y).divided_by(n).remainder;

    return EllipticCurvePoint { new_x, new_y };
}

EllipticCurvePoint EllipticCurvePoint::twice(UnsignedBigInteger n, UnsignedBigInteger a)
{
    auto two = UnsignedBigInteger::from_base10("2");
    auto three = UnsignedBigInteger::from_base10("3");

    auto i = x.multiplied_by(x).multiplied_by(three).plus(a);
    auto j = SignedBigInteger::from_base10("1");
    // TODO
    //auto j = (y.multiplied_by(two)).mod_inverse(n);

    i = (i.multiplied_by(j)).divided_by(n).remainder;
    j = i.multiplied_by(i);
    j = (j.minus(x.multiplied_by(two))).divided_by(n).remainder;

    auto new_x = j;
    auto new_y = (i.multiplied_by(x.minus(j))).minus(y).divided_by(n).remainder;

    return EllipticCurvePoint { new_x, new_y };
}

EllipticCurvePoint EllipticCurvePoint::multiply(UnsignedBigInteger n, UnsignedBigInteger a, UnsignedBigInteger scalar)
{
    EllipticCurvePoint doubled = *this;
    EllipticCurvePoint value { 0, 0 };

    bool set = false;
    String binary = "10101010";
    // TODO
    //String binary = scalar.to_base2();

    for (int i = binary.length(); i >= 0; i--) {
        if (binary[i] == '1') {
            if (set) {
                value = value.add(doubled, n);
            } else {
                value = doubled;
                set = true;
            }
        }
        doubled = doubled.twice(n, a);
    }

    return value;
}

}
}
