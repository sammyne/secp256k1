// Copyright 2010 The Go Authors. All rights reserved.
// Copyright 2011 ThePiachu. All rights reserved.
// Copyright 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package koblitz

// References:
//   [SECG]: Recommended Elliptic Curve Domain Parameters
//     http://www.secg.org/sec2-v2.pdf
//
//   [GECC]: Guide to Elliptic Curve Cryptography (Hankerson, Menezes, Vanstone)

// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var (
	// fieldOne is simply the integer 1 in field representation.  It is
	// used to avoid needing to create it multiple times during the internal
	// arithmetic.
	fieldOne = new(fieldVal).SetInt(1)
)

// KoblitzCurve supports a koblitz curve implementation that fits the ECC Curve
// interface from crypto/elliptic.
type KoblitzCurve struct {
	*elliptic.CurveParams
	q         *big.Int
	H         int      // cofactor of the curve.
	halfOrder *big.Int // half the order N

	// byteSize is simply the bit size / 8 and is provided for convenience
	// since it is calculated repeatedly.
	byteSize int

	// bytePoints
	bytePoints *[32][256][3]fieldVal

	// The next 6 values are used specifically for endomorphism
	// optimizations in ScalarMult.

	// lambda must fulfill lambda^3 = 1 mod N where N is the order of G.
	lambda *big.Int

	// beta must fulfill beta^3 = 1 mod P where P is the prime field of the
	// curve.
	beta *fieldVal

	// See the EndomorphismVectors in gensecp256k1.go to see how these are
	// derived.
	a1 *big.Int
	b1 *big.Int
	a2 *big.Int
	b2 *big.Int
}

// Add returns the sum of (x1,y1) and (x2,y2). Part of the elliptic.Curve
// interface.
func (curve *KoblitzCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// A point at infinity is the identity according to the group law for
	// elliptic curve cryptography.  Thus, ∞ + P = P and P + ∞ = P.
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}

	// Convert the affine coordinates from big integers to field values
	// and do the point addition in Jacobian projective space.
	fx1, fy1 := curve.bigAffineToField(x1, y1)
	fx2, fy2 := curve.bigAffineToField(x2, y2)
	fx3, fy3, fz3 := new(fieldVal), new(fieldVal), new(fieldVal)
	fOne := new(fieldVal).SetInt(1)
	curve.addJacobian(fx1, fy1, fOne, fx2, fy2, fOne, fx3, fy3, fz3)

	// Convert the Jacobian coordinate field values back to affine big
	// integers.
	return curve.fieldJacobianToBigAffine(fx3, fy3, fz3)
}

// Double returns 2*(x1,y1). Part of the elliptic.Curve interface.
func (curve *KoblitzCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// Convert the affine coordinates from big integers to field values
	// and do the point doubling in Jacobian projective space.
	fx1, fy1 := curve.bigAffineToField(x1, y1)
	fx3, fy3, fz3 := new(fieldVal), new(fieldVal), new(fieldVal)
	fOne := new(fieldVal).SetInt(1)
	curve.doubleJacobian(fx1, fy1, fOne, fx3, fy3, fz3)

	// Convert the Jacobian coordinate field values back to affine big
	// integers.
	return curve.fieldJacobianToBigAffine(fx3, fy3, fz3)
}

// IsOnCurve returns boolean if the point (x,y) is on the curve.
// Part of the elliptic.Curve interface. This function differs from the
// crypto/elliptic algorithm since a = 0 not -3.
func (curve *KoblitzCurve) IsOnCurve(x, y *big.Int) bool {
	// Convert big ints to field values for faster arithmetic.
	fx, fy := curve.bigAffineToField(x, y)

	// Elliptic curve equation for secp256k1 is: y^2 = x^3 + 7
	y2 := new(fieldVal).SquareVal(fy).Normalize()
	result := new(fieldVal).SquareVal(fx).Mul(fx).AddInt(7).Normalize()
	return y2.Equals(result)
}

// Params returns the parameters for the curve.
func (curve *KoblitzCurve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// NAF takes a positive integer k and returns the Non-Adjacent Form (NAF) as two
// byte slices.  The first is where 1s will be.  The second is where -1s will
// be.  NAF is convenient in that on average, only 1/3rd of its values are
// non-zero.  This is algorithm 3.30 from [GECC].
//
// Essentially, this makes it possible to minimize the number of operations
// since the resulting ints returned will be at least 50% 0s.
func NAF(k []byte) ([]byte, []byte) {
	// The essence of this algorithm is that whenever we have consecutive 1s
	// in the binary, we want to put a -1 in the lowest bit and get a bunch
	// of 0s up to the highest bit of consecutive 1s.  This is due to this
	// identity:
	// 2^n + 2^(n-1) + 2^(n-2) + ... + 2^(n-k) = 2^(n+1) - 2^(n-k)
	//
	// The algorithm thus may need to go 1 more bit than the length of the
	// bits we actually have, hence bits being 1 bit longer than was
	// necessary.  Since we need to know whether adding will cause a carry,
	// we go from right-to-left in this addition.
	var carry, curIsOne, nextIsOne bool
	// these default to zero
	retPos := make([]byte, len(k)+1)
	retNeg := make([]byte, len(k)+1)
	for i := len(k) - 1; i >= 0; i-- {
		curByte := k[i]
		for j := uint(0); j < 8; j++ {
			curIsOne = curByte&1 == 1
			if j == 7 {
				if i == 0 {
					nextIsOne = false
				} else {
					nextIsOne = k[i-1]&1 == 1
				}
			} else {
				nextIsOne = curByte&2 == 2
			}
			if carry {
				if curIsOne {
					// This bit is 1, so continue to carry
					// and don't need to do anything.
				} else {
					// We've hit a 0 after some number of
					// 1s.
					if nextIsOne {
						// Start carrying again since
						// a new sequence of 1s is
						// starting.
						retNeg[i+1] += 1 << j
					} else {
						// Stop carrying since 1s have
						// stopped.
						carry = false
						retPos[i+1] += 1 << j
					}
				}
			} else if curIsOne {
				if nextIsOne {
					// If this is the start of at least 2
					// consecutive 1s, set the current one
					// to -1 and start carrying.
					retNeg[i+1] += 1 << j
					carry = true
				} else {
					// This is a singleton, not consecutive
					// 1s.
					retPos[i+1] += 1 << j
				}
			}
			curByte >>= 1
		}
	}
	if carry {
		retPos[0] = 1
		return retPos, retNeg
	}
	return retPos[1:], retNeg[1:]
}

// ScalarMult returns k*(Bx, By) where k is a big endian integer.
// Part of the elliptic.Curve interface.
func (curve *KoblitzCurve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	// Point Q = ∞ (point at infinity).
	qx, qy, qz := new(fieldVal), new(fieldVal), new(fieldVal)

	// Decompose K into k1 and k2 in order to halve the number of EC ops.
	// See Algorithm 3.74 in [GECC].
	k1, k2, signK1, signK2 := curve.splitK(curve.moduloReduce(k))

	// The main equation here to remember is:
	//   k * P = k1 * P + k2 * ϕ(P)
	//
	// P1 below is P in the equation, P2 below is ϕ(P) in the equation
	p1x, p1y := curve.bigAffineToField(Bx, By)
	p1yNeg := new(fieldVal).NegateVal(p1y, 1)
	p1z := new(fieldVal).SetInt(1)

	// NOTE: ϕ(x,y) = (βx,y).  The Jacobian z coordinate is 1, so this math
	// goes through.
	p2x := new(fieldVal).Mul2(p1x, curve.beta)
	p2y := new(fieldVal).Set(p1y)
	p2yNeg := new(fieldVal).NegateVal(p2y, 1)
	p2z := new(fieldVal).SetInt(1)

	// Flip the positive and negative values of the points as needed
	// depending on the signs of k1 and k2.  As mentioned in the equation
	// above, each of k1 and k2 are multiplied by the respective point.
	// Since -k * P is the same thing as k * -P, and the group law for
	// elliptic curves states that P(x, y) = -P(x, -y), it's faster and
	// simplifies the code to just make the point negative.
	if signK1 == -1 {
		p1y, p1yNeg = p1yNeg, p1y
	}
	if signK2 == -1 {
		p2y, p2yNeg = p2yNeg, p2y
	}

	// NAF versions of k1 and k2 should have a lot more zeros.
	//
	// The Pos version of the bytes contain the +1s and the Neg versions
	// contain the -1s.
	k1PosNAF, k1NegNAF := NAF(k1)
	k2PosNAF, k2NegNAF := NAF(k2)
	k1Len := len(k1PosNAF)
	k2Len := len(k2PosNAF)

	m := k1Len
	if m < k2Len {
		m = k2Len
	}

	// Add left-to-right using the NAF optimization.  See algorithm 3.77
	// from [GECC].  This should be faster overall since there will be a lot
	// more instances of 0, hence reducing the number of Jacobian additions
	// at the cost of 1 possible extra doubling.
	var k1BytePos, k1ByteNeg, k2BytePos, k2ByteNeg byte
	for i := 0; i < m; i++ {
		// Since we're going left-to-right, pad the front with 0s.
		if i < m-k1Len {
			k1BytePos = 0
			k1ByteNeg = 0
		} else {
			k1BytePos = k1PosNAF[i-(m-k1Len)]
			k1ByteNeg = k1NegNAF[i-(m-k1Len)]
		}
		if i < m-k2Len {
			k2BytePos = 0
			k2ByteNeg = 0
		} else {
			k2BytePos = k2PosNAF[i-(m-k2Len)]
			k2ByteNeg = k2NegNAF[i-(m-k2Len)]
		}

		for j := 7; j >= 0; j-- {
			// Q = 2 * Q
			curve.doubleJacobian(qx, qy, qz, qx, qy, qz)

			if k1BytePos&0x80 == 0x80 {
				curve.addJacobian(qx, qy, qz, p1x, p1y, p1z,
					qx, qy, qz)
			} else if k1ByteNeg&0x80 == 0x80 {
				curve.addJacobian(qx, qy, qz, p1x, p1yNeg, p1z,
					qx, qy, qz)
			}

			if k2BytePos&0x80 == 0x80 {
				curve.addJacobian(qx, qy, qz, p2x, p2y, p2z,
					qx, qy, qz)
			} else if k2ByteNeg&0x80 == 0x80 {
				curve.addJacobian(qx, qy, qz, p2x, p2yNeg, p2z,
					qx, qy, qz)
			}
			k1BytePos <<= 1
			k1ByteNeg <<= 1
			k2BytePos <<= 1
			k2ByteNeg <<= 1
		}
	}

	// Convert the Jacobian coordinate field values back to affine big.Ints.
	return curve.fieldJacobianToBigAffine(qx, qy, qz)
}

// ScalarBaseMult returns k*G where G is the base point of the group and k is a
// big endian integer.
// Part of the elliptic.Curve interface.
func (curve *KoblitzCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	newK := curve.moduloReduce(k)
	diff := len(curve.bytePoints) - len(newK)

	// Point Q = ∞ (point at infinity).
	qx, qy, qz := new(fieldVal), new(fieldVal), new(fieldVal)

	// curve.bytePoints has all 256 byte points for each 8-bit window. The
	// strategy is to add up the byte points. This is best understood by
	// expressing k in base-256 which it already sort of is.
	// Each "digit" in the 8-bit window can be looked up using bytePoints
	// and added together.
	for i, byteVal := range newK {
		p := curve.bytePoints[diff+i][byteVal]
		curve.addJacobian(qx, qy, qz, &p[0], &p[1], &p[2], qx, qy, qz)
	}
	return curve.fieldJacobianToBigAffine(qx, qy, qz)
}

// QPlus1Div4 returns the Q+1/4 constant for the curve for use in calculating
// square roots via exponention.
func (curve *KoblitzCurve) QPlus1Div4() *big.Int {
	return curve.q
}

var initonce sync.Once
var secp256k1 KoblitzCurve

func initAll() {
	initS256()
}

// fromHex converts the passed hex string into a big integer pointer and will
// panic is there is an error.  This is only provided for the hard-coded
// constants so errors in the source code can bet detected. It will only (and
// must only) be called for initialization purposes.
func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex in source file: " + s)
	}
	return r
}

func initS256() {
	// Curve parameters taken from [SECG] section 2.4.1.
	secp256k1.CurveParams = new(elliptic.CurveParams)
	secp256k1.P = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secp256k1.N = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secp256k1.B = fromHex("0000000000000000000000000000000000000000000000000000000000000007")
	secp256k1.Gx = fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secp256k1.Gy = fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	secp256k1.BitSize = 256
	secp256k1.q = new(big.Int).Div(new(big.Int).Add(secp256k1.P,
		big.NewInt(1)), big.NewInt(4))
	secp256k1.H = 1
	secp256k1.halfOrder = new(big.Int).Rsh(secp256k1.N, 1)

	// Provided for convenience since this gets computed repeatedly.
	secp256k1.byteSize = secp256k1.BitSize / 8

	// Deserialize and set the pre-computed table used to accelerate scalar
	// base multiplication.  This is hard-coded data, so any errors are
	// panics because it means something is wrong in the source code.
	if err := loadS256BytePoints(); err != nil {
		panic(err)
	}

	// Next 6 constants are from Hal Finney's bitcointalk.org post:
	// https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
	// May he rest in peace.
	//
	// They have also been independently derived from the code in the
	// EndomorphismVectors function in gensecp256k1.go.
	secp256k1.lambda = fromHex("5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72")
	secp256k1.beta = new(fieldVal).SetHex("7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE")
	secp256k1.a1 = fromHex("3086D221A7D46BCDE86C90E49284EB15")
	secp256k1.b1 = fromHex("-E4437ED6010E88286F547FA90ABFE4C3")
	secp256k1.a2 = fromHex("114CA50F7A8E2F3F657C1108D9D44CFD8")
	secp256k1.b2 = fromHex("3086D221A7D46BCDE86C90E49284EB15")

	// Alternatively, we can use the parameters below, however, they seem
	//  to be about 8% slower.
	// secp256k1.lambda = fromHex("AC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CE")
	// secp256k1.beta = new(fieldVal).SetHex("851695D49A83F8EF919BB86153CBCB16630FB68AED0A766A3EC693D68E6AFA40")
	// secp256k1.a1 = fromHex("E4437ED6010E88286F547FA90ABFE4C3")
	// secp256k1.b1 = fromHex("-3086D221A7D46BCDE86C90E49284EB15")
	// secp256k1.a2 = fromHex("3086D221A7D46BCDE86C90E49284EB15")
	// secp256k1.b2 = fromHex("114CA50F7A8E2F3F657C1108D9D44CFD8")
}

// S256 returns a Curve which implements secp256k1.
func S256() *KoblitzCurve {
	initonce.Do(initAll)
	return &secp256k1
}
