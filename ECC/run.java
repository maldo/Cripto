import java.math.BigInteger;
import java.util.Formatter;


public class run
{

	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	private static final BigInteger THREE = BigInteger.valueOf(3L);
	
	private static final BigInteger[] O = { ZERO, ONE, ZERO };
	
	private static final BigInteger[] parametres1 = new BigInteger[] {
		BigInteger.ONE, BigInteger.valueOf(4), BigInteger.valueOf(23) };
	
	private static final BigInteger[] parametres2 = new BigInteger[] {
		BigInteger.ONE, BigInteger.valueOf(5), BigInteger.valueOf(23) };
	
	private static BigInteger[] buildPoint(long x, long y) {
		return new BigInteger[] { BigInteger.valueOf(x), BigInteger.valueOf(y),
				BigInteger.ONE };
	}
	
	private static void checkPoint(BigInteger[] p, BigInteger[] P, long x,
			long y) {
		checkPoint(p, P);

		assert p[0].longValue() == x;
		assert p[1].longValue() == y;
		assert !p[2].equals(BigInteger.ZERO);
	}
	
	private static void checkPoint(BigInteger[] P, BigInteger[] param) {
		final BigInteger x = P[0], y = P[1], z = P[2];
		final BigInteger a = param[0], b = param[1], p = param[2];

		if (z.equals(BigInteger.ZERO)) {
			return;
		}

		BigInteger x3 = x.pow(3);
		BigInteger y2 = y.pow(2);
		BigInteger pd = x3.add(a.multiply(x)).add(b);

		assert pd.mod(p).equals(y2.mod(p));
	}
	
	private static void checkPointInf(BigInteger[] p, BigInteger[] P) {
		checkPoint(p, P);

		assert p[2].equals(BigInteger.ZERO);
	}
	
	public static void main(String[] args)
	{
		runInvers();
		runSuma();
		runMultiple();
		runFirma();

		System.out.println("va bien");
	}

	private static void runSuma()
	{
		BigInteger[] P = buildPoint(4, 7);
		BigInteger[] Q = buildPoint(13, 11);
		BigInteger[] r;

		r = ecc.suma(P, Q, parametres1);
		checkPoint(r, parametres1, 15, 6);

		r = ecc.suma(P, P, parametres1);
		checkPoint(r, parametres1, 10, 18);

		r = ecc.invers(P, parametres1);
		checkPoint(r, parametres1, 4, 16);

		r = ecc.suma(P, r, parametres1);
		checkPointInf(r, parametres1);

		r = ecc.suma(P, O, parametres1);
		checkPoint(r, parametres1, 4, 7);

		// Duplicar punto si coordenada Y es zero.
		P = buildPoint(16, 0);
		r = ecc.suma(P, P, parametres2);
		checkPointInf(r, parametres2);
		
	}

	private static void runInvers()
	{
		BigInteger[] r = buildPoint(0, 2);
		BigInteger[] i = ecc.invers(r, parametres1);
		checkPoint(i, parametres1, 0, 21);
		
	}
	
	private static void runMultiple() {
		BigInteger[] P = buildPoint(0, 2);
		BigInteger[] r;

		r = ecc.multiple(BigInteger.valueOf(1), P, parametres1);
		checkPoint(r, parametres1, 0, 2);

		r = ecc.multiple(BigInteger.valueOf(2), P, parametres1);
		checkPoint(r, parametres1, 13, 12);

		r = ecc.multiple(BigInteger.valueOf(3), P, parametres1);
		checkPoint(r, parametres1, 11, 9);

		r = ecc.multiple(BigInteger.valueOf(4), P, parametres1);
		checkPoint(r, parametres1, 1, 12);

		r = ecc.multiple(BigInteger.valueOf(5), P, parametres1);
		checkPoint(r, parametres1, 7, 20);

		r = ecc.multiple(BigInteger.valueOf(6), P, parametres1);
		checkPoint(r, parametres1, 9, 11);

		r = ecc.multiple(BigInteger.valueOf(7), P, parametres1);
		checkPoint(r, parametres1, 15, 6);

		r = ecc.multiple(BigInteger.valueOf(8), P, parametres1);
		checkPoint(r, parametres1, 14, 5);

		r = ecc.multiple(BigInteger.valueOf(11), P, parametres1);
		checkPoint(r, parametres1, 10, 5);

		r = ecc.multiple(BigInteger.valueOf(17), P, parametres1);
		checkPoint(r, parametres1, 17, 14);

		r = ecc.multiple(BigInteger.valueOf(23), P, parametres1);
		checkPoint(r, parametres1, 9, 12);

		r = ecc.multiple(BigInteger.valueOf(29), P, parametres1);
		checkPointInf(r, parametres1);

		r = ecc.multiple(BigInteger.valueOf(30), P, parametres1);
		checkPoint(r, parametres1, 0, 2);

		r = ecc.multiple(BigInteger.valueOf(31), P, parametres1);
		checkPoint(r, parametres1, 13, 12);
	}

	private static void runFirma() {
		/* Els seguents paràmetres venen del RFC 4754 */

		/* n, Gx, Gy, a, b, p */
		BigInteger[] parametres = {
				new BigInteger(
						"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
						16),
				new BigInteger(
						"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
						16),
				new BigInteger(
						"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
						16),
				BigInteger.valueOf(-3),
				new BigInteger(
						"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
						16),
				new BigInteger(
						"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
						16) };

		/* hash missatge, valor aleatori */
		ecc
				.runMode(
						new BigInteger(
								"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
								16),
						new BigInteger(
								"9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE",
								16));

		/* clau privada */
		byte[] b = ecc
				.firmarECCDSA(
						new String("abc").getBytes(),
						new BigInteger(
								"DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F",
								16), parametres);

		assert (byteArrayToHexString(b)
				.equals("616263cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315"));

		/* clau publica */
		assert ecc
				.verificarECCDSA(
						b,
						new BigInteger[] {
								new BigInteger(
										"2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970",
										16),
								new BigInteger(
										"6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D",
										16) }, parametres);

		ecc.clearRunMode();
	}
	
	private static String byteArrayToHexString(byte[] a) {
		Formatter f = new Formatter(new StringBuilder(a.length * 2));

		for (int n = 0; n < a.length; n++) {
			f.format("%02x", a[n] & 0xFF);
		}

		return f.toString();
	}

}
