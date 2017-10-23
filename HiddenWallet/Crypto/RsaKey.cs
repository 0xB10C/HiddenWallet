using NBitcoin;
using NBitcoin.Crypto;
using HiddenWallet.BouncyCastle.Asn1;
using HiddenWallet.BouncyCastle.Asn1.Pkcs;
using HiddenWallet.BouncyCastle.Asn1.X509;
using HiddenWallet.BouncyCastle.Crypto;
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
	public class RsaKey
	{
		private static BigInteger RSA_F4 = BigInteger.ValueOf(65537);
		internal readonly RsaPrivateCrtKeyParameters _Key;

		public RsaKey()
		{
			var gen = new RsaKeyPairGenerator();
			gen.Init(new RsaKeyGenerationParameters(RSA_F4, NBitcoinSecureRandom.Instance, KeySize, 100)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
			var pair = gen.GenerateKeyPair();
			_Key = (RsaPrivateCrtKeyParameters)pair.Private;
			_PubKey = new RsaPubKey((RsaKeyParameters)pair.Public);
		}

		public RsaKey(byte[] bytes)
		{
			if (bytes == null)
				throw new ArgumentNullException(nameof(bytes));
			try
			{
				DerSequence seq2 = GetRSASequence(bytes);
				var s = new RsaPrivateKeyStructure(seq2);
				_Key = new RsaPrivateCrtKeyParameters(s.Modulus, s.PublicExponent, s.PrivateExponent, s.Prime1, s.Prime2, s.Exponent1, s.Exponent2, s.Coefficient);
				_PubKey = new RsaPubKey(new RsaKeyParameters(false, s.Modulus, s.PublicExponent));
			}
			catch (Exception)
			{
				throw new FormatException("Invalid RSA Key");
			}
		}

		public byte[] Sign(byte[] data, out uint160 nonce)
		{
			while (true)
			{
				byte[] output = new byte[256];
				nonce = new uint160(RandomUtils.GetBytes(20));
				Sha512Digest sha512 = new Sha512Digest();
				var msg = ByteHelpers.Combine(nonce.ToBytes(), data);
				var generator = new Mgf1BytesGenerator(sha512);
				generator.Init(new MgfParameters(msg));
				generator.GenerateBytes(output, 0, output.Length);
				var input = new BigInteger(1, output);
				if (input.CompareTo(_Key.Modulus) >= 0)
					continue;
				var engine = new RsaBlindedEngine();
				engine.Init(true, _Key);

				return engine.ConvertOutput(engine.ProcessBlock(input));
			}
		}

		internal BigInteger Decrypt(BigInteger encrypted)
		{
			if (encrypted == null)
				throw new ArgumentNullException(nameof(encrypted));
			if (encrypted.CompareTo(_Key.Modulus) >= 0)
				throw new DataLengthException("input too large for RSA cipher.");

			RsaBlindedEngine engine = new RsaBlindedEngine();
			engine.Init(false, _Key);
			return engine.ProcessBlock(encrypted);
		}

		internal static DerSequence GetRSASequence(byte[] bytes)
		{
			Asn1InputStream decoder = new Asn1InputStream(bytes);
			var seq = (DerSequence)decoder.ReadObject();
			if (!((DerInteger)seq[0]).Value.Equals(BigInteger.Zero))
				throw new Exception();
			if (!((DerSequence)seq[1])[0].Equals(AlgID.ObjectID) ||
			   !((DerSequence)seq[1])[1].Equals(AlgID.Parameters))
				throw new Exception();
			var seq2b = (DerOctetString)seq[2];
			decoder = new Asn1InputStream(seq2b.GetOctets());
			var seq2 = (DerSequence)decoder.ReadObject();
			return seq2;
		}

		private readonly RsaPubKey _PubKey;
		public RsaPubKey PubKey
		{
			get
			{
				return _PubKey;
			}
		}

		public byte[] ToBytes()
		{
			RsaPrivateKeyStructure keyStruct = new RsaPrivateKeyStructure(
				_Key.Modulus,
				_Key.PublicExponent,
				_Key.Exponent,
				_Key.P,
				_Key.Q,
				_Key.DP,
				_Key.DQ,
				_Key.QInv);

			var privInfo = new PrivateKeyInfo(AlgID, keyStruct.ToAsn1Object());
			return privInfo.ToAsn1Object().GetEncoded();
		}

		public int GetKeySize()
		{
			return PubKey.GetKeySize();
		}

		internal static AlgorithmIdentifier AlgID = new AlgorithmIdentifier(
					new DerObjectIdentifier("1.2.840.113549.1.1.1"), DerNull.Instance);
		public static readonly int KeySize = 2048;
	}
}
