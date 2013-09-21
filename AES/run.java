import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * Para probar que la practica funciona, vamos a usar vectores que nos da el
 * NIST, los llamados Aes Known Answer Test (KAT) que se pueden descargar
 * http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip no los vamos a
 * probar todos, pero si unos cuantos, probar con diferentes longitudes de K,
 * ..... Y despues tambien usaremos los apendices del fips para comprobar otras
 * partes, y ya por ultimo "comparar" que den la misma salida, el AES de java
 * con nuestro AES
 * 
 * 
 * Para probar la ultima parte de la practica es necesario descargarse Java
 * Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 6
 * de la pagina de oracle
 * (http://www.oracle.com/technetwork/java/javase/downloads/index.html) para
 * poder usar las claves de 192 y 256 bytes. Ahora mismo esta puesto que la
 * clave que elige pero despues se vuelve a la clave default de longitud 128
 * 
 * @author Alberto Maldonado
 * 
 */

public class run
{

	static final String AZ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/*
	 * Assert no funcionaba asi que hemos tenido que hacer algo parecido
	 */
	private static void check(boolean condition)
	{
		if (!condition)
		{
			throw new Error();
		}
	}

	/*
	 * No cuesta nada asegurarse...
	 */
	private static void runByteSub()
	{
		check((aes.byteSub((byte) 0) & 0xFF) == 0x63);
		check((aes.byteSub((byte) 1) & 0xFF) == 0x7C);
		check((aes.byteSub((byte) 2) & 0xFF) == 0x77);
		check((aes.byteSub((byte) 13) & 0xFF) == 0xD7);
		check((aes.byteSub((byte) 131) & 0xFF) == 0xEC);
		check((aes.byteSub((byte) 222) & 0xFF) == 0x1D);
		check((aes.byteSub((byte) 225) & 0xFF) == 0xF8);
		check((aes.byteSub((byte) 253) & 0xFF) == 0x54);
		check((aes.byteSub((byte) 254) & 0xFF) == 0xbb);
		check((aes.byteSub((byte) 255) & 0xFF) == 0x16);
	}

	/**
	 * Datos extraidos de la wikipedia
	 * http://en.wikipedia.org/wiki/Rijndael_mix_columns#Test_vectors
	 * */
	private static void runMixColumns()
	{
		byte[][] s = new byte[4][4];

		s[0][0] = (byte) 0xdb;
		s[1][0] = (byte) 0x13;
		s[2][0] = (byte) 0x53;
		s[3][0] = (byte) 0x45;
		s[0][1] = (byte) 0xf2;
		s[1][1] = (byte) 0x0a;
		s[2][1] = (byte) 0x22;
		s[3][1] = (byte) 0x5c;
		s[0][2] = (byte) 0x01;
		s[1][2] = (byte) 0x01;
		s[2][2] = (byte) 0x01;
		s[3][2] = (byte) 0x01;
		s[0][3] = (byte) 0xc6;
		s[1][3] = (byte) 0xc6;
		s[2][3] = (byte) 0xc6;
		s[3][3] = (byte) 0xc6;

		s = aes.mixColumn(s);
		check((s[0][0] & 0xFF) == 0x8e);
		check((s[1][0] & 0xFF) == 0x4d);
		check((s[2][0] & 0xFF) == 0xa1);
		check((s[3][0] & 0xFF) == 0xbc);
		check((s[0][1] & 0xFF) == 0x9f);
		check((s[1][1] & 0xFF) == 0xdc);
		check((s[2][1] & 0xFF) == 0x58);
		check((s[3][1] & 0xFF) == 0x9d);
		check((s[0][2] & 0xFF) == 1);
		check((s[1][2] & 0xFF) == 1);
		check((s[2][2] & 0xFF) == 1);
		check((s[3][2] & 0xFF) == 1);
		check((s[0][3] & 0xFF) == 0xc6);
		check((s[1][3] & 0xFF) == 0xc6);
		check((s[2][3] & 0xFF) == 0xc6);
		check((s[3][3] & 0xFF) == 0xc6);

		s = aes.invMixColumn(s);
		check((s[0][0] & 0xFF) == 0xdb);
		check((s[1][0] & 0xFF) == 0x13);
		check((s[2][0] & 0xFF) == 0x53);
		check((s[3][0] & 0xFF) == 0x45);
		check((s[0][1] & 0xFF) == 0xf2);
		check((s[1][1] & 0xFF) == 0x0a);
		check((s[2][1] & 0xFF) == 0x22);
		check((s[3][1] & 0xFF) == 0x5c);
		check((s[0][2] & 0xFF) == 1);
		check((s[1][2] & 0xFF) == 1);
		check((s[2][2] & 0xFF) == 1);
		check((s[3][2] & 0xFF) == 1);
		check((s[0][3] & 0xFF) == 0xc6);
		check((s[1][3] & 0xFF) == 0xc6);
		check((s[2][3] & 0xFF) == 0xc6);
		check((s[3][3] & 0xFF) == 0xc6);

		s[0][0] = (byte) 0x01;
		s[1][0] = (byte) 0x01;
		s[2][0] = (byte) 0x01;
		s[3][0] = (byte) 0x01;
		s[0][1] = (byte) 0xc6;
		s[1][1] = (byte) 0xc6;
		s[2][1] = (byte) 0xc6;
		s[3][1] = (byte) 0xc6;
		s[0][2] = (byte) 0xd4;
		s[1][2] = (byte) 0xd4;
		s[2][2] = (byte) 0xd4;
		s[3][2] = (byte) 0xd5;
		s[0][3] = (byte) 0x2d;
		s[1][3] = (byte) 0x26;
		s[2][3] = (byte) 0x31;
		s[3][3] = (byte) 0x4c;

		s = aes.mixColumn(s);
		check((s[0][0] & 0xFF) == 0x01);
		check((s[1][0] & 0xFF) == 0x01);
		check((s[2][0] & 0xFF) == 0x01);
		check((s[3][0] & 0xFF) == 0x01);
		check((s[0][1] & 0xFF) == 0xc6);
		check((s[1][1] & 0xFF) == 0xc6);
		check((s[2][1] & 0xFF) == 0xc6);
		check((s[3][1] & 0xFF) == 0xc6);
		check((s[0][2] & 0xFF) == 0xd5);
		check((s[1][2] & 0xFF) == 0xd5);
		check((s[2][2] & 0xFF) == 0xd7);
		check((s[3][2] & 0xFF) == 0xd6);
		check((s[0][3] & 0xFF) == 0x4d);
		check((s[1][3] & 0xFF) == 0x7e);
		check((s[2][3] & 0xFF) == 0xbd);
		check((s[3][3] & 0xFF) == 0xf8);

		s = aes.invMixColumn(s);
		check((s[0][0] & 0xFF) == 0x01);
		check((s[1][0] & 0xFF) == 0x01);
		check((s[2][0] & 0xFF) == 0x01);
		check((s[3][0] & 0xFF) == 0x01);
		check((s[0][1] & 0xFF) == 0xc6);
		check((s[1][1] & 0xFF) == 0xc6);
		check((s[2][1] & 0xFF) == 0xc6);
		check((s[3][1] & 0xFF) == 0xc6);
		check((s[0][2] & 0xFF) == 0xd4);
		check((s[1][2] & 0xFF) == 0xd4);
		check((s[2][2] & 0xFF) == 0xd4);
		check((s[3][2] & 0xFF) == 0xd5);
		check((s[0][3] & 0xFF) == 0x2d);
		check((s[1][3] & 0xFF) == 0x26);
		check((s[2][3] & 0xFF) == 0x31);
		check((s[3][3] & 0xFF) == 0x4c);

	}

	private static byte[] hexStringToByteArray(String s)
	{
		final int len = s.length();
		byte[] b = new byte[len / 2];
		for (int i = 0; i < len; i += 2)
		{
			byte upper = (byte) Character.digit(s.charAt(i), 16);
			byte lower = (byte) Character.digit(s.charAt(i + 1), 16);
			b[i / 2] = (byte) ((upper << 4) | lower);
		}
		return b;
	}

	private static String byteArrayToHexString(byte[] a)
	{
		Formatter f = new Formatter(new StringBuilder(a.length * 2));

		for (int n = 0; n < a.length; n++)
		{
			f.format("%02x", a[n] & 0xFF);
		}

		return f.toString();
	}

	private static String toHexBytes(String s)
	{
		byte[] b = s.getBytes();
		StringBuilder h = new StringBuilder(s.length() * 2);
		Formatter f = new Formatter(h);

		for (int i = 0; i < b.length; i++)
		{
			f.format("%02x", b[i] & 0xFF);
		}

		return f.toString();
	}

	private static String expandedKeyToString(byte[][][] k)
	{
		StringBuilder b = new StringBuilder(k.length * 4 * 4 * 4);
		Formatter f = new Formatter(b);
		for (int n = 0; n < k.length; n++)
		{
			for (int j = 0; j < 4; j++)
			{
				for (int i = 0; i < 4; i++)
				{
					f.format("%02x ", k[n][i][j] & 0xFF);
				}
			}
			f.flush();
			b.append('\n');
		}

		return b.toString();
	}

	private static byte[][] stringToState(String str)
	{
		byte[][] s = new byte[4][4];
		StringReader r = new StringReader(str);

		try
		{
			for (int j = 0; j < 4; j++)
			{
				for (int i = 0; i < 4; i++)
				{
					int val = Character.digit(r.read(), 16) * 16;
					val += Character.digit(r.read(), 16);
					s[i][j] = (byte) val;
				}
			}
		}
		catch (IOException e)
		{
			throw new AssertionError("Shouldn't happen");
		}

		return s;
	}

	/* FIPS-197.pdf */
	private static void runKeyExpansion()
	{
		byte[][][] k;
		String expected;

		k = aes.keyExpansion(
				new BigInteger(new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28,
						(byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab,
						(byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf,
						0x4f, 0x3c }), 4, 10);
		expected = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c \n"
				+ "a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05 \n"
				+ "f2 c2 95 f2 7a 96 b9 43 59 35 80 7a 73 59 f6 7f \n"
				+ "3d 80 47 7d 47 16 fe 3e 1e 23 7e 44 6d 7a 88 3b \n"
				+ "ef 44 a5 41 a8 52 5b 7f b6 71 25 3b db 0b ad 00 \n"
				+ "d4 d1 c6 f8 7c 83 9d 87 ca f2 b8 bc 11 f9 15 bc \n"
				+ "6d 88 a3 7a 11 0b 3e fd db f9 86 41 ca 00 93 fd \n"
				+ "4e 54 f7 0e 5f 5f c9 f3 84 a6 4f b2 4e a6 dc 4f \n"
				+ "ea d2 73 21 b5 8d ba d2 31 2b f5 60 7f 8d 29 2f \n"
				+ "ac 77 66 f3 19 fa dc 21 28 d1 29 41 57 5c 00 6e \n"
				+ "d0 14 f9 a8 c9 ee 25 89 e1 3f 0c c8 b6 63 0c a6 \n";
		String s = expandedKeyToString(k);
		check(s.equals(expected));

		k = aes.keyExpansion(new BigInteger(new byte[] { (byte) 0x8e, 0x73,
				(byte) 0xb0, (byte) 0xf7, (byte) 0xda, 0x0e, 0x64, 0x52,
				(byte) 0xc8, 0x10, (byte) 0xf3, 0x2b, (byte) 0x80, (byte) 0x90,
				0x79, (byte) 0xe5, 0x62, (byte) 0xf8, (byte) 0xea, (byte) 0xd2,
				0x52, 0x2c, 0x6b, 0x7b }), 6, 12);
		expected = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 \n"
				+ "62 f8 ea d2 52 2c 6b 7b fe 0c 91 f7 24 02 f5 a5 \n"
				+ "ec 12 06 8e 6c 82 7f 6b 0e 7a 95 b9 5c 56 fe c2 \n"
				+ "4d b7 b4 bd 69 b5 41 18 85 a7 47 96 e9 25 38 fd \n"
				+ "e7 5f ad 44 bb 09 53 86 48 5a f0 57 21 ef b1 4f \n"
				+ "a4 48 f6 d9 4d 6d ce 24 aa 32 63 60 11 3b 30 e6 \n"
				+ "a2 5e 7e d5 83 b1 cf 9a 27 f9 39 43 6a 94 f7 67 \n"
				+ "c0 a6 94 07 d1 9d a4 e1 ec 17 86 eb 6f a6 49 71 \n"
				+ "48 5f 70 32 22 cb 87 55 e2 6d 13 52 33 f0 b7 b3 \n"
				+ "40 be eb 28 2f 18 a2 59 67 47 d2 6b 45 8c 55 3e \n"
				+ "a7 e1 46 6c 94 11 f1 df 82 1f 75 0a ad 07 d7 53 \n"
				+ "ca 40 05 38 8f cc 50 06 28 2d 16 6a bc 3c e7 b5 \n"
				+ "e9 8b a0 6f 44 8c 77 3c 8e cc 72 04 01 00 22 02 \n";
		s = expandedKeyToString(k);
		check(s.equals(expected));

		k = aes.keyExpansion(new BigInteger(new byte[] { 0x60, 0x3d,
				(byte) 0xeb, 0x10, 0x15, (byte) 0xca, 0x71, (byte) 0xbe, 0x2b,
				0x73, (byte) 0xae, (byte) 0xf0, (byte) 0x85, 0x7d, 0x77,
				(byte) 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08,
				(byte) 0xd7, 0x2d, (byte) 0x98, 0x10, (byte) 0xa3, 0x09, 0x14,
				(byte) 0xdf, (byte) 0xf4 }), 8, 14);
		expected = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 \n"
				+ "1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4 \n"
				+ "9b a3 54 11 8e 69 25 af a5 1a 8b 5f 20 67 fc de \n"
				+ "a8 b0 9c 1a 93 d1 94 cd be 49 84 6e b7 5d 5b 9a \n"
				+ "d5 9a ec b8 5b f3 c9 17 fe e9 42 48 de 8e be 96 \n"
				+ "b5 a9 32 8a 26 78 a6 47 98 31 22 29 2f 6c 79 b3 \n"
				+ "81 2c 81 ad da df 48 ba 24 36 0a f2 fa b8 b4 64 \n"
				+ "98 c5 bf c9 be bd 19 8e 26 8c 3b a7 09 e0 42 14 \n"
				+ "68 00 7b ac b2 df 33 16 96 e9 39 e4 6c 51 8d 80 \n"
				+ "c8 14 e2 04 76 a9 fb 8a 50 25 c0 2d 59 c5 82 39 \n"
				+ "de 13 69 67 6c cc 5a 71 fa 25 63 95 96 74 ee 15 \n"
				+ "58 86 ca 5d 2e 2f 31 d7 7e 0a f1 fa 27 cf 73 c3 \n"
				+ "74 9c 47 ab 18 50 1d da e2 75 7e 4f 74 01 90 5a \n"
				+ "ca fa aa e3 e4 d5 9b 34 9a df 6a ce bd 10 19 0d \n"
				+ "fe 48 90 d1 e6 18 8d 0b 04 6d f3 44 70 6c 63 1e \n";
		s = expandedKeyToString(k);
		check(s.equals(expected));
	}

	private static void runXifrarAESCBC()
	{
		byte[] r;
		int longk;

		/************* Extraidos de CBCGFSbox192e.txt *****************/
		longk = 192;
		byte[] m = hexStringToByteArray("1b077a6af4b7f98229de786d7516b639");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("1b666527257241b0771b077a6af4b71b077a6af4b71b077a6af4b7a6af4b7752474571b077a6af4b754654ad45cf54");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("941a4773058224e1ef66d10e0a6ee782");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("51719783d3185a535bd75adc65071ce1");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"000000000000000000000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		/************* Extraidos de CBCGFSbox128e.txt *****************/
		longk = 128;
		m = hexStringToByteArray("f34481ec3cc627bacd5dc3fb08f273e6");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"00000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"00000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("b26aeb1874e47ca8358ff22378f09144");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"00000000000000000000000000000000", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"00000000000000000000000000000000", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		/************* Extraidos de CBCGFSbox256e.txt *****************/
		longk = 256;

		m = hexStringToByteArray("014730f80ac625fe84f026c60bfd547d");
		r = aes.xifrarAESCBC(
				m,
				new BigInteger(
						"0000000000000000000000000000000000000000000000000000000000000000",
						16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(
				r,
				new BigInteger(
						"0000000000000000000000000000000000000000000000000000000000000000",
						16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("8a560769d605868ad80d819bdba03771");
		r = aes.xifrarAESCBC(
				m,
				new BigInteger(
						"0000000000000000000000000000000000000000000000000000000000000000",
						16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(
				r,
				new BigInteger(
						"0000000000000000000000000000000000000000000000000000000000000000",
						16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		/************* Extraidos de CBCKeySbox128e.txt *****************/
		longk = 128;

		m = hexStringToByteArray("00000000000000000000000000000000");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"10a58869d74be5a374cf867cfb473859", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"10a58869d74be5a374cf867cfb473859", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		m = hexStringToByteArray("00000000000000000000000000000000");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"febd9a24d8b65c1c787d50a4ed3619a9", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"febd9a24d8b65c1c787d50a4ed3619a9", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		/************* Extraidos de CBCKeySbox192e.txt *****************/
		longk = 192;

		m = hexStringToByteArray("00000000000000000000000000000000");
		r = aes.xifrarAESCBC(m, new BigInteger(
				"e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd", 16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(r, new BigInteger(
				"e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd", 16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		/************* Extraidos de CBCKeySbox256e.txt *****************/
		longk = 256;

		m = hexStringToByteArray("00000000000000000000000000000000");
		r = aes.xifrarAESCBC(
				m,
				new BigInteger(
						"c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
						16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(
				r,
				new BigInteger(
						"c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
						16), longk);

		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));

		Random xx = new Random();
		m = hexStringToByteArray(toHexBytes(rndString(xx.nextInt(128))));
		r = aes.xifrarAESCBC(
				m,
				new BigInteger(
						"c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
						16), longk,
				stringToState("00000000000000000000000000000000"));

		r = aes.desxifrarAES(
				r,
				new BigInteger(
						"c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
						16), longk);
		check(byteArrayToHexString(r).equals(byteArrayToHexString(m)));
	}

	public static void main(String[] args) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException
	{
		// Empezamos probando las funciones que constituyen rijndeal
		System.out.println("Empezamos con las pruebas....");

		System.out.println("ByteSub....");
		runByteSub();
		System.out.println("MixColumns....");
		runMixColumns();
		System.out.println("keyExpansion....");
		runKeyExpansion();
		System.out.println("XifrarAES....");
		runXifrarAESCBC();
		System.out.println("Hasta aqui hemos pasado las pruebas del fisp");
		runJAES();
		System.out.println("Se pasan pruebas contra el AES de java");
		System.out.println("FIN");

	}

	private static void runJAES() throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException
	{
		Random r = new Random();
		int total = r.nextInt(5000);

		System.out
				.println("Se van a ejecutar "
						+ total
						+ " pruebas contra el AES implementado en las librerias de java (esperar al mensaje final)");

		for (int i = 1; i < total + 1; i++)
		{

			int xxx = r.nextInt(3) + 1;

			// Elegimos aleatoreamente una longitud de llave
			int longkey = 128;
			if (xxx == 1) longkey = 128;
			else if (xxx == 2) longkey = 192;
			else if (xxx == 3) longkey = 256;

			/*
			 * la siguiente linia es la que hay descomentar una vez se disponga
			 * de Unlimited Strengh de java 
			 */
			longkey = 128;

			/*
			 * Generamos un String totalmente aleatorio de tamano entre 0 y i
			 */
			byte[] input = hexStringToByteArray(toHexBytes(rndString(r
					.nextInt(i))));

			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(longkey); // 192 and 256 bits may not be available

			// Generamos la llave
			SecretKey skey = kgen.generateKey();
			byte[] key = skey.getEncoded();

			byte[] output = null;
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			/*
			 * Se podria elegir cualquier otro modo y padding solo vamos a
			 * comparar los textos descifrados
			 */
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			output = cipher.doFinal(input);
			// System.out.println(byteArrayToHexString(input));
			cipher.init(Cipher.DECRYPT_MODE, keySpec, cipher.getParameters());
			byte[] fin = cipher.doFinal(output);
			// System.out.println(byteArrayToHexString(fin));

			byte[] mout = aes.xifrarAES(input, new BigInteger(
					"10000000100000001000000010000000", 16), longkey);
			// System.out.println(byteArrayToHexString(mout));

			byte[] mf = aes.desxifrarAES(mout, new BigInteger(
					"10000000100000001000000010000000", 16), longkey);
			// System.out.println(byteArrayToHexString(mf));

			// java aes
			check(byteArrayToHexString(input).equals(byteArrayToHexString(fin)));
			// my aes
			check(byteArrayToHexString(input).equals(byteArrayToHexString(mf)));
			// java aes vs my java aes
			if (!byteArrayToHexString(fin).equals(byteArrayToHexString(mf)))
			{
				System.out.println("Error en la prueba " + i);
				System.out
						.println("Plaintext : " + byteArrayToHexString(input));
				System.out.println("Descifrado Java : "
						+ byteArrayToHexString(fin));
				System.out.println("Descifrado AES : "
						+ byteArrayToHexString(mf));
				return;
			}

			// System.out.println(byteArrayToHexString(output));

		}
		System.out.println("Se ha ejecutado correctamente " + total + " veces");
	}

	private static String rndString(int length)
	{
		Random r = new Random();
		StringBuffer sb = new StringBuffer();
		for (int i = length; i > 0; i--)
		{
			sb.append(AZ.charAt(r.nextInt(AZ.length())));
		}
		return sb.toString();
	}

}
