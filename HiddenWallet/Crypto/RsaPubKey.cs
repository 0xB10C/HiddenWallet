using NBitcoin;
using NBitcoin.Crypto;
using HiddenWallet.BouncyCastle.Asn1;
using HiddenWallet.BouncyCastle.Asn1.Pkcs;
using HiddenWallet.BouncyCastle.Asn1.X509;
using HiddenWallet.BouncyCastle.Crypto.Digests;
using HiddenWallet.BouncyCastle.Crypto.Engines;
using HiddenWallet.BouncyCastle.Crypto.Generators;
using HiddenWallet.BouncyCastle.Crypto.Parameters;
using HiddenWallet.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HiddenWallet.Crypto
{
	public class RsaPubKey
	{
		public RsaPubKey()
		{

		}

		public RsaPubKey(byte[] bytes)
		{
			if (bytes == null)
				throw new ArgumentNullException(nameof(bytes));
			try
			{
				DerSequence seq2 = RsaKey.GetRSASequence(bytes);
				var s = new RsaPublicKeyStructure(seq2);
				_Key = new RsaKeyParameters(false, s.Modulus, s.PublicExponent);
			}
			catch (Exception)
			{
				throw new FormatException("Invalid RSA Key");
			}
		}

		internal readonly RsaKeyParameters _Key;
		internal RsaPubKey(RsaKeyParameters key)
		{
			_Key = key ?? throw new ArgumentNullException(nameof(key));
		}

		public byte[] ToBytes()
		{
			RsaPublicKeyStructure keyStruct = new RsaPublicKeyStructure(
				_Key.Modulus,
				_Key.Exponent);
			var privInfo = new PrivateKeyInfo(RsaKey.AlgID, keyStruct.ToAsn1Object());
			return privInfo.ToAsn1Object().GetEncoded();
		}

		public bool Verify(byte[] signature, byte[] data, uint160 nonce)
		{
			byte[] output = new byte[256];
			var msg = ByteHelpers.Combine(nonce.ToBytes(), data);
			Sha512Digest sha512 = new Sha512Digest();
			var generator = new Mgf1BytesGenerator(sha512);
			generator.Init(new MgfParameters(msg));
			generator.GenerateBytes(output, 0, output.Length);
			var input = new BigInteger(1, output);
			if (input.CompareTo(_Key.Modulus) >= 0)
				return false;
			if (signature.Length > 256)
				return false;
			var signatureInt = new BigInteger(1, signature);
			if (signatureInt.CompareTo(_Key.Modulus) >= 0)
				return false;
			var engine = new RsaBlindedEngine();
			engine.Init(false, _Key);
			return input.Equals(engine.ProcessBlock(signatureInt));
		}

		public uint256 GetHash()
		{
			return Hashes.Hash256(ToBytes());
		}

		internal BigInteger Encrypt(BigInteger data)
		{
			if (data == null)
				throw new ArgumentNullException(nameof(data));
			if (data.CompareTo(_Key.Modulus) >= 0)
				throw new ArgumentException("input too large for RSA cipher.");

			RsaBlindedEngine engine = new RsaBlindedEngine();
			engine.Init(true, _Key);
			return engine.ProcessBlock(data);
		}

		public BigInteger Blind(BigInteger data, ref BlindFactor blindFactor)
		{
			if (data == null)
				throw new ArgumentNullException(nameof(data));
			EnsureInitializeBlindFactor(ref blindFactor);
			return Blind(blindFactor._Value.ModPow(_Key.Exponent, _Key.Modulus), data);
		}

		private void EnsureInitializeBlindFactor(ref BlindFactor blindFactor)
		{
			blindFactor = blindFactor ?? new BlindFactor(CryptoHelpers.GenerateEncryptableInteger(_Key));
		}

		public BigInteger RevertBlind(BigInteger data, BlindFactor blindFactor)
		{
			if (data == null)
				throw new ArgumentNullException(nameof(data));
			if (blindFactor == null)
				throw new ArgumentNullException(nameof(blindFactor));
			EnsureInitializeBlindFactor(ref blindFactor);
			var ai = blindFactor._Value.ModInverse(_Key.Modulus);
			return Blind(ai.ModPow(_Key.Exponent, _Key.Modulus), data);
		}

		internal BigInteger Unblind(BigInteger data, BlindFactor blindFactor)
		{
			if (data == null)
				throw new ArgumentNullException(nameof(data));
			if (blindFactor == null)
				throw new ArgumentNullException(nameof(blindFactor));
			EnsureInitializeBlindFactor(ref blindFactor);
			return Blind(blindFactor._Value.ModInverse(_Key.Modulus), data);
		}

		internal BigInteger Blind(BigInteger multiplier, BigInteger msg)
		{
			return msg.Multiply(multiplier).Mod(_Key.Modulus);
		}

		public int GetKeySize()
		{
			return _Key.Modulus.BitLength;
		}

		public override bool Equals(object obj)
		{
			RsaPubKey item = obj as RsaPubKey;
			if (item == null)
				return false;
			return _Key.Equals(item._Key);
		}
		public static bool operator ==(RsaPubKey a, RsaPubKey b)
		{
			if (ReferenceEquals(a, b))
				return true;
			if (((object)a == null) || ((object)b == null))
				return false;
			return a._Key.Equals(b._Key);
		}

		public static bool operator !=(RsaPubKey a, RsaPubKey b)
		{
			return !(a == b);
		}

		public override int GetHashCode()
		{
			return _Key.GetHashCode();
		}
	}
}