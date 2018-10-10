package koblitz

import "math/big"

// addZ1EqualsZ2 adds two Jacobian points that are already known to have the
// same z value and stores the result in (x3, y3, z3).  That is to say
// (x1, y1, z1) + (x2, y2, z1) = (x3, y3, z3).  It performs faster addition than
// the generic add routine since less arithmetic is needed due to the known
// equivalence.
func (curve *KoblitzCurve) addZ1EqualsZ2(x1, y1, z1, x2, y2, x3, y3, z3 *fieldVal) {
	// To compute the point addition efficiently, this implementation splits
	// the equation into intermediate elements which are used to minimize
	// the number of field multiplications using a slightly modified version
	// of the method shown at:
	// http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-zadd-2007-m
	//
	// In particular it performs the calculations using the following:
	// A = X2-X1, B = A^2, C=Y2-Y1, D = C^2, E = X1*B, F = X2*B
	// X3 = D-E-F, Y3 = C*(E-X3)-Y1*(F-E), Z3 = Z1*A
	//
	// This results in a cost of 5 field multiplications, 2 field squarings,
	// 9 field additions, and 0 integer multiplications.

	// When the x coordinates are the same for two points on the curve, the
	// y coordinates either must be the same, in which case it is point
	// doubling, or they are opposite and the result is the point at
	// infinity per the group law for elliptic curve cryptography.
	x1.Normalize()
	y1.Normalize()
	x2.Normalize()
	y2.Normalize()
	if x1.Equals(x2) {
		if y1.Equals(y2) {
			// Since x1 == x2 and y1 == y2, point doubling must be
			// done, otherwise the addition would end up dividing
			// by zero.
			curve.doubleJacobian(x1, y1, z1, x3, y3, z3)
			return
		}

		// Since x1 == x2 and y1 == -y2, the sum is the point at
		// infinity per the group law.
		x3.SetInt(0)
		y3.SetInt(0)
		z3.SetInt(0)
		return
	}

	// Calculate X3, Y3, and Z3 according to the intermediate elements
	// breakdown above.
	var a, b, c, d, e, f fieldVal
	var negX1, negY1, negE, negX3 fieldVal
	// why need mag as 2
	negX1.Set(x1).Negate(1)                // negX1 = -X1 (mag: 2)
	negY1.Set(y1).Negate(1)                // negY1 = -Y1 (mag: 2)
	a.Set(&negX1).Add(x2)                  // A = X2-X1 (mag: 3)
	b.SquareVal(&a)                        // B = A^2 (mag: 1)
	c.Set(&negY1).Add(y2)                  // C = Y2-Y1 (mag: 3)
	d.SquareVal(&c)                        // D = C^2 (mag: 1)
	e.Mul2(x1, &b)                         // E = X1*B (mag: 1)
	negE.Set(&e).Negate(1)                 // negE = -E (mag: 2)
	f.Mul2(x2, &b)                         // F = X2*B (mag: 1)
	x3.Add2(&e, &f).Negate(3).Add(&d)      // X3 = D-E-F (mag: 5)
	negX3.Set(x3).Negate(5).Normalize()    // negX3 = -X3 (mag: 1)
	y3.Set(y1).Mul(f.Add(&negE)).Negate(3) // Y3 = -(Y1*(F-E)) (mag: 4)
	y3.Add(e.Add(&negX3).Mul(&c))          // Y3 = C*(E-X3)+Y3 (mag: 5)
	z3.Mul2(z1, &a)                        // Z3 = Z1*A (mag: 1)

	// Normalize the resulting field values to a magnitude of 1 as needed.
	x3.Normalize()
	y3.Normalize()
}

// bigAffineToField takes an affine point (x, y) as big integers and converts
// it to an affine point as field values.
func (curve *KoblitzCurve) bigAffineToField(x, y *big.Int) (*fieldVal,
	*fieldVal) {
	x3, y3 := new(fieldVal), new(fieldVal)
	x3.SetByteSlice(x.Bytes())
	y3.SetByteSlice(y.Bytes())

	return x3, y3
}

// fieldJacobianToBigAffine takes a Jacobian point (x, y, z) as field values and
// converts it to an affine point as big integers.
func (curve *KoblitzCurve) fieldJacobianToBigAffine(x, y,
	z *fieldVal) (*big.Int, *big.Int) {
	// Inversions are expensive and both point addition and point doubling
	// are faster when working with points that have a z value of one.  So,
	// if the point needs to be converted to affine, go ahead and normalize
	// the point itself at the same time as the calculation is the same.
	var zInv, tempZ fieldVal
	zInv.Set(z).Inverse()   // zInv = Z^-1
	tempZ.SquareVal(&zInv)  // tempZ = Z^-2
	x.Mul(&tempZ)           // X = X/Z^2 (mag: 1)
	y.Mul(tempZ.Mul(&zInv)) // Y = Y/Z^3 (mag: 1)
	z.SetInt(1)             // Z = 1 (mag: 1)

	// Normalize the x and y values.
	x.Normalize()
	y.Normalize()

	// Convert the field values for the now affine point to big.Ints.
	x3, y3 := new(big.Int), new(big.Int)
	x3.SetBytes(x.Bytes()[:])
	y3.SetBytes(y.Bytes()[:])
	return x3, y3
}
