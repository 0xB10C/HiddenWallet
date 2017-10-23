using HiddenWallet.Crypto;
using System;
using System.Linq;
using System.Text;

namespace NBitcoin
{
	public static class BitcoinStreamExtensions
	{
		public static void ReadWriteC(this BitcoinStream bs, ref uint256[] values)
		{
			var mutable = values?.Select(h => h.AsBitcoinSerializable()).ToArray();
			bs.ReadWrite(ref mutable);
			if (!bs.Serializing)
			{
				values = mutable.Select(m => m.Value).ToArray();
			}
		}
		public static void ReadWriteC(this BitcoinStream bs, ref PubKey pubKey)
		{
			if (bs.Serializing)
			{
				var bytes = pubKey.ToBytes();
				bs.Inner.Write(bytes, 0, 33);
			}
			else
			{
				pubKey = new PubKey(bs.Inner.ReadBytes(33));
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref Network network)
		{
			if (bs.Serializing)
			{
				var str = network.ToString();
				bs.ReadWriteC(ref str);
			}
			else
			{
				var str = string.Empty;
				bs.ReadWriteC(ref str);
				network = Network.GetNetwork(str);
			}
		}

		internal static void ReadWriteC(this BitcoinStream bs, ref HiddenWallet.BouncyCastle.Math.BigInteger integer)
		{
			if (bs.Serializing)
			{
				var str = integer.ToByteArrayUnsigned();
				bs.ReadWriteAsVarString(ref str);
			}
			else
			{
				byte[] str = null;
				bs.ReadWriteAsVarString(ref str);
				integer = new HiddenWallet.BouncyCastle.Math.BigInteger(1, str);
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref string str)
		{
			if (bs.Serializing)
			{
				var bytes = Encoding.ASCII.GetBytes(str);
				bs.ReadWriteAsVarString(ref bytes);
			}
			else
			{
				byte[] bytes = null;
				bs.ReadWriteAsVarString(ref bytes);
				str = Encoding.ASCII.GetString(bytes);
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref RsaPubKey pubKey)
		{
			if (bs.Serializing)
			{
				var bytes = pubKey == null ? new byte[0] : pubKey.ToBytes();
				bs.ReadWriteAsVarString(ref bytes);
			}
			else
			{
				byte[] bytes = null;
				bs.ReadWriteAsVarString(ref bytes);
				pubKey = bytes.Length == 0 ? null : new RsaPubKey(bytes);
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref PermutationTestProof proof)
		{
			if (bs.Serializing)
			{
				if (proof == null)
				{
					uint o = 0;
					bs.ReadWriteAsVarInt(ref o);
					return;
				}
				var len = (uint)proof.Signatures.Length;
				bs.ReadWriteAsVarInt(ref len);
				for (int i = 0; i < len; i++)
				{
					var sig = proof.Signatures[i];
					bs.ReadWriteAsVarString(ref sig);
				}
			}
			else
			{
				uint len = 0;
				bs.ReadWriteAsVarInt(ref len);
				if (len == 0)
				{
					proof = null;
					return;
				}
				if (len > bs.MaxArraySize)
					throw new ArgumentOutOfRangeException("Array is too big");
				var signatures = new byte[len][];
				for (int i = 0; i < len; i++)
				{
					byte[] sig = null;
					bs.ReadWriteAsVarString(ref sig);
					signatures[i] = sig;
				}
				proof = new PermutationTestProof(signatures);
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref PoupardSternProof proof)
		{
			if (bs.Serializing)
			{
				if (proof == null)
				{
					uint o = 0;
					bs.ReadWriteAsVarInt(ref o);
					return;
				}
				var len = (uint)proof.XValues.Length;
				bs.ReadWriteAsVarInt(ref len);
				for (int i = 0; i < len; i++)
				{
					var n = proof.XValues[i];
					bs.ReadWriteC(ref n);
				}
				var yvalue = proof.YValue;
				bs.ReadWriteC(ref yvalue);
			}
			else
			{
				uint len = 0;
				bs.ReadWriteAsVarInt(ref len);
				if (len == 0)
				{
					proof = null;
					return;
				}
				if (len > bs.MaxArraySize)
					throw new ArgumentOutOfRangeException("Array is too big");
				var xValues = new HiddenWallet.BouncyCastle.Math.BigInteger[len];
				for (int i = 0; i < len; i++)
				{
					HiddenWallet.BouncyCastle.Math.BigInteger b = null;
					bs.ReadWriteC(ref b);
					xValues[i] = b;
				}
				HiddenWallet.BouncyCastle.Math.BigInteger yValue = null;
				bs.ReadWriteC(ref yValue);
				proof = new PoupardSternProof(Tuple.Create(xValues, yValue));
			}
		}

		public static void ReadWriteC(this BitcoinStream bs, ref Money money)
		{
			if (bs.Serializing)
			{
				var satoshis = checked((ulong)money.Satoshi);
				bs.ReadWrite(ref satoshis);
			}
			else
			{
				var satoshis = 0UL;
				bs.ReadWrite(ref satoshis);
				money = Money.Satoshis(satoshis);
			}
		}
	}
}
