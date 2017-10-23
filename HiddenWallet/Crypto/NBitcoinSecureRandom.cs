using System;
using System.Collections.Generic;
using System.Text;
using NBitcoin;
using HiddenWallet.BouncyCastle.Security;

namespace HiddenWallet.Crypto
{
	internal class NBitcoinSecureRandom : SecureRandom
	{

		private static readonly NBitcoinSecureRandom _Instance = new NBitcoinSecureRandom();
		public static NBitcoinSecureRandom Instance
		{
			get
			{
				return _Instance;
			}
		}
		private NBitcoinSecureRandom()
		{

		}

		public override void NextBytes(byte[] buffer)
		{
			RandomUtils.GetBytes(buffer);
		}
	}
}
