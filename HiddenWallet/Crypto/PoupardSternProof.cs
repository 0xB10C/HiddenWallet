using System;
using System.Collections.Generic;
using System.Text;
using HiddenWallet.BouncyCastle.Math;

namespace HiddenWallet.Crypto
{
	public class PoupardSternProof
	{
		internal PoupardSternProof(Tuple<BigInteger[], BigInteger> proof)
		{
			if (proof == null)
				throw new ArgumentNullException(nameof(proof));
			XValues = proof.Item1;
			YValue = proof.Item2;
		}
		internal BigInteger[] XValues
		{
			get; set;
		}
		internal BigInteger YValue
		{
			get; set;
		}
	}
}
