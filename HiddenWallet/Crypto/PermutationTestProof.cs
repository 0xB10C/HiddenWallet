using System;
using System.Collections.Generic;
using System.Text;

namespace HiddenWallet.Crypto
{
	public class PermutationTestProof
	{
		public PermutationTestProof(byte[][] proof)
		{
			Signatures = proof ?? throw new ArgumentNullException(nameof(proof));
		}

		public byte[][] Signatures
		{
			get; set;
		}
	}
}
