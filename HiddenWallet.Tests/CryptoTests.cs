using HiddenWallet.BouncyCastle.Math;
using HiddenWallet.Crypto;
using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace HiddenWallet.Tests
{
    public class CryptoTests
    {
		[Fact]
		public void CanGenerateParseAndSaveRsaKey()
		{
			RsaKey key = new RsaKey();
			RsaKey key2 = new RsaKey(key.ToBytes());
			Assert.True(key.ToBytes().SequenceEqual(key2.ToBytes()));
			Assert.True(key.PubKey.ToBytes().SequenceEqual(key2.PubKey.ToBytes()));
			Assert.True(new RsaPubKey(key.PubKey.ToBytes()).ToBytes().SequenceEqual(key2.PubKey.ToBytes()));
			Assert.Throws<FormatException>(() => new RsaKey(new byte[1]));
		}

		[Fact]
		public void CanSignAndVerify()
		{
			RsaKey key = new RsaKey();
			for (int i = 0; i < 100; i++)
			{
				var data = RandomUtils.GetBytes(234);
				var sig = key.Sign(data, out uint160 nonce);
				Assert.True(key.PubKey.Verify(sig, data, nonce));
			}
		}

		[Fact]
		public void TestChacha()
		{
			byte[] msg = Encoding.UTF8.GetBytes("123123123123123123123123123123");
			var key1 = Encoding.ASCII.GetBytes("xxxxxxxxxxxxxxxx");
			var iv1 = Encoding.ASCII.GetBytes("aaaaaaaa");
			var encrypted = CryptoHelpers.ChachaEncrypt(msg, ref key1, ref iv1);
			Assert.False(encrypted.SequenceEqual(msg));
			var decrypted = CryptoHelpers.ChachaDecrypt(encrypted, key1);
			Assert.True(decrypted.SequenceEqual(msg));
		}

		[Fact]
		public void CanBlind()
		{
			RsaKey key = new RsaKey();
			BlindFactor blindFactor = null;
			var stringToBlind = "blind me, please~!@#$%^&*()";

			BigInteger data = new BigInteger(Encoding.ASCII.GetBytes(stringToBlind));
			BigInteger blindedData = key.PubKey.Blind(data, ref blindFactor);
			BigInteger unblindedData = key.PubKey.RevertBlind(blindedData, blindFactor);
			var unblindedString = Encoding.ASCII.GetString(unblindedData.ToByteArray());
			Assert.Equal(stringToBlind, unblindedString);

			RsaKey key2 = new RsaKey();
			BlindFactor blindFactor2 = null;
			var stringToBlind2 = "foo";

			BigInteger data2 = new BigInteger(Encoding.ASCII.GetBytes(stringToBlind2));
			BigInteger blindedData2 = key.PubKey.Blind(data2, ref blindFactor2);
			BigInteger unblindedData2 = key.PubKey.RevertBlind(blindedData2, blindFactor2);
			var unblindedString2 = Encoding.ASCII.GetString(unblindedData2.ToByteArray());
			Assert.Equal(stringToBlind2, unblindedString2);

			var wronglyUnblindedData = key.PubKey.RevertBlind(blindedData2, blindFactor);
			Assert.NotEqual(stringToBlind2, Encoding.ASCII.GetString(wronglyUnblindedData.ToByteArray()));
		}

		[Fact]
		public void CanBlindSign()
		{
			RsaKey blindingkey = new RsaKey();
			RsaKey signingKey = new RsaKey();
			BlindFactor blindFactor = null;
			var stringToBlind = "blind me, please~!@#$%^&*()";
			
			BigInteger data = new BigInteger(Encoding.ASCII.GetBytes(stringToBlind));
			// 1. blind data
			BigInteger blindedData = blindingkey.PubKey.Blind(data, ref blindFactor);
			// 2. sign blinded data
			byte[] signature = signingKey.Sign(blindedData.ToByteArray(), out uint160 nonce);
			// verify blinded data is properly signed
			Assert.True(signingKey.PubKey.Verify(signature, blindedData.ToByteArray(), nonce));
			// 3. unblind blinded data
			BigInteger unblindedData = blindingkey.PubKey.RevertBlind(blindedData, blindFactor);
			// verify unblinded data is the same as the original data
			Assert.Equal(data, unblindedData);
			// verify unblinded string is the same as the original string
			var unblindedString = Encoding.ASCII.GetString(unblindedData.ToByteArray());
			Assert.Equal(stringToBlind, unblindedString);
			// 4. verify original data is signed
			var unblindedSignature = blindingkey.PubKey.RevertBlind(new BigInteger(signature), blindFactor);
			Assert.True(signingKey.PubKey.Verify(unblindedSignature.ToByteArray(), unblindedData.ToByteArray(), nonce));
		}
	}
}
