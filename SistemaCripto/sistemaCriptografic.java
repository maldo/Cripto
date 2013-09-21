import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

class sistemaCriptografic
{
	private static SecureRandom srandom = new SecureRandom();

	public static byte[] enviarMissatge(byte[] M, BigInteger clauDeFirma,
			BigInteger clauPrivadaECC, BigInteger[] clauPublicaECC,
			BigInteger[] parametresECC)
	{
		byte[] MF = ecc.firmarECCDSA(M, clauDeFirma, parametresECC);

		//Generamos 32 bytes aleatorios
		byte[] KSE = new byte[32];
		srandom.nextBytes(KSE);
		BigInteger KS = ecc.ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC,
				parametresECC);
		
		//Nuestro aes ya aplica el modo CBC
		byte[] EMF = aes.xifrarAES(MF, KS, 256);
		
		//Concatenamos
		byte[] res = new byte[KSE.length + EMF.length];
		System.arraycopy(KSE, 0, res, 0, KSE.length);
		System.arraycopy(EMF, 0, res, KSE.length, EMF.length);
		return res;
	}

	public static byte[] rebreMissatge(byte[] C,
			BigInteger[] clauDeVerificacioDeFirma, BigInteger clauPrivadaECC,
			BigInteger[] clauPublicaECC, BigInteger[] parametresECC)
	{
		//Partimos C
		byte[] KSE = Arrays.copyOfRange(C, 0, 32);
		byte[] EMF = Arrays.copyOfRange(C, 32, C.length);

		//Necesitamos la clave para el aes
		BigInteger KS = ecc.ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC,
				parametresECC);

		byte[] MF = aes.desxifrarAES(EMF, KS, 256);

		boolean ver = ecc.verificarECCDSA(MF, clauDeVerificacioDeFirma,
				parametresECC);
		
		//Concatenamos
		byte[] res = new byte[MF.length + 1];
		System.arraycopy(MF, 0, res, 0, MF.length);
		
		if (ver)
		{
			res[MF.length] = (byte) 0;
		}
		else
		{
			res[MF.length] = (byte) 0xff;
		}
		
		return res;
	}
}