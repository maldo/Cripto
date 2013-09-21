import java.math.BigInteger;
import java.util.Arrays;

class test
{
	static BigInteger[] parametrosECC = {
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

	public static void main(String[] args)
	{
		byte[] M = "Esto es un test para ver si todo funciona".getBytes();

		BigInteger[] claveFirma = ecc.clausECC(parametrosECC);
		BigInteger[] claveCifrado = ecc.clausECC(parametrosECC);

		BigInteger claveDeFirma = claveFirma[0];
		BigInteger[] claveDeVerificacionDeFirma = Arrays.copyOfRange(
				claveFirma, 1, 3);

		BigInteger clavePrivadaECC = claveCifrado[0];
		BigInteger[] clavePublicaECC = Arrays.copyOfRange(claveCifrado, 1, 3);

		byte[] C = sistemaCriptografic.enviarMissatge(M, claveDeFirma,
				clavePrivadaECC, clavePublicaECC, parametrosECC);

		byte[] M2 = sistemaCriptografic.rebreMissatge(C,
				claveDeVerificacionDeFirma, clavePrivadaECC, clavePublicaECC,
				parametrosECC);

		if (M2[M2.length - 1] == 0)
		{// La firma es correcta M2||F
			if (Arrays.equals(M, Arrays.copyOfRange(M2, 0, M2.length - 65)))
			{
				// M y M2 son iguales no ha habido cosas raras
				System.out.println("Firma correcta");
			}
			else
			{
				System.out.println("Le ha pasado algo a M");
			}
		}
		else
		{
			System.out.println("Firma Incorrecta");
		}
	}
}
