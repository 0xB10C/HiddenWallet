using HiddenWallet.BouncyCastle.Crypto.Engines;
using HiddenWallet.BouncyCastle.Crypto.Parameters;
using HiddenWallet.BouncyCastle.Math;
using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;

namespace HiddenWallet.Crypto
{
    public static class CryptoHelpers
    {
		public static byte[] ChachaEncrypt(byte[] data, ref byte[] key)
		{
			byte[] iv = null;
			return ChachaEncrypt(data, ref key, ref iv);
		}

		public static byte[] ChachaEncrypt(byte[] data, ref byte[] key, ref byte[] iv)
		{
			ChaChaEngine engine = new ChaChaEngine();
			key = key ?? RandomUtils.GetBytes(ChachaKeySize);
			iv = iv ?? RandomUtils.GetBytes(ChachaKeySize / 2);
			engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
			byte[] result = new byte[iv.Length + data.Length];
			Array.Copy(iv, result, iv.Length);
			engine.ProcessBytes(data, 0, data.Length, result, iv.Length);
			return result;
		}

		public const int ChachaKeySize = 128 / 8;
		public static byte[] ChachaDecrypt(byte[] encrypted, byte[] key)
		{
			ChaChaEngine engine = new ChaChaEngine();
			var iv = new byte[ChachaKeySize / 2];
			Array.Copy(encrypted, iv, iv.Length);
			engine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
			byte[] result = new byte[encrypted.Length - iv.Length];
			engine.ProcessBytes(encrypted, iv.Length, encrypted.Length - iv.Length, result, 0);
			return result;
		}

		internal static BigInteger GenerateEncryptableInteger(RsaKeyParameters key)
		{
			while (true)
			{
				var bytes = RandomUtils.GetBytes(RsaKey.KeySize / 8);
				BigInteger input = new BigInteger(1, bytes);
				if (input.CompareTo(key.Modulus) >= 0)
					continue;
				return input;
			}
		}
	}
}
