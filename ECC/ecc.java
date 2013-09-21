import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ecc
{

	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger UNO = BigInteger.ONE;
	private static final BigInteger DOS = BigInteger.valueOf(2);
	private static final BigInteger TRES = BigInteger.valueOf(3);
	private static final int X = 0;
	private static final int Y = 1;
	private static final int Z = 2;
	private static SecureRandom sRandom = new SecureRandom();
	private static boolean debugging = false;
	private static BigInteger runHash, runRandom;

	/**
	 * 
	 * @param P
	 *            P punt de la corba donat per 3 coordenades (x; y; z), (si z =
	 *            0 es el punt de l'infinit)
	 * @param ParametresCorba
	 *            {a; b; p}, corresponents a la corba y2 = x3 + ax + b mod p
	 * @return una llista {Rx,Ry,Rz} que representa l'invers de P, R = P (si Rz
	 *         = 0, es el punt de l'in nit)
	 */
	public static BigInteger[] invers(BigInteger[] P,
			BigInteger[] ParametresCorba)
	{
		BigInteger[] inv = new BigInteger[3];

		inv[X] = P[X];
		inv[Y] = P[Y].negate().mod(ParametresCorba[2]);
		inv[Z] = P[Z];

		return inv;
	}

	/**
	 * 
	 * @param P
	 *            punt de la corba donats per 3 coordenades (x; y; z), (si z = 0
	 *            es el punt de l'infinit)
	 * @param Q
	 *            punt de la corba donats per 3 coordenades (x; y; z)
	 * @param ParametresCorba
	 *            = {a; b; p}, corresponents a la corba y
	 * @return una llista {Rx,Ry,Rz} que representa el punt R = P + Q (si Rz =
	 *         0, es el punt de l'infinit)
	 */
	public static BigInteger[] suma(BigInteger[] P, BigInteger[] Q,
			BigInteger[] ParametresCorba)
	{
		/*
		 * -> P + O = P -> P + (-P) = O -> si Q = (x2; y2) distinto P, aleshores
		 * P + Q = (x',L(x1-x') - y1 mod p); on x'= L^2 - x1 - x2 mod p^i
		 * 
		 * -> si Q = P -> L = (3x^2(1) + a)(2y(1))^-1 mod p -> si Q distinto P
		 * -> L = (y(2) - y(1))(x(2) - x(1))^-1 mod p
		 */

		BigInteger a = ParametresCorba[0];
		BigInteger p = ParametresCorba[2];
		BigInteger x, y, z;
		BigInteger x1 = P[X];
		BigInteger y1 = P[Y];
		BigInteger z1 = P[Z];
		BigInteger x2 = Q[X];
		BigInteger y2 = Q[Y];
		BigInteger z2 = Q[Z];

		if (z1.equals(ZERO) && z2.equals(ZERO))
		{
			return new BigInteger[] { ZERO, ZERO, ZERO };
		}
		else if (z1.equals(ZERO))
		{
			return Q;
		}
		else if (z2.equals(ZERO))
		{
			return P;
		}
		else
		{
			if (iguales(P, invers(Q, ParametresCorba))) return new BigInteger[] {
					ZERO, UNO, ZERO };
			else
			{
				BigInteger L;
				if (iguales(P, Q))
				{
					L = x1.modPow(DOS, p).multiply(TRES).add(a)
							.multiply(y1.multiply(DOS).modInverse(p)).mod(p);
				}
				else
				{
					L = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p))
							.mod(p);
				}

				BigInteger s = L.modPow(DOS, p).subtract(x1).subtract(x2)
						.mod(p);
				x = s;
				y = L.multiply(x1.subtract(s)).subtract(y1).mod(p);
				z = UNO;
			}
		}

		return new BigInteger[] { x, y, z };

	}

	public static BigInteger[] multiple(BigInteger k, BigInteger[] P,
			BigInteger[] ParametresCorba)
	{
		BigInteger R[] = new BigInteger[] { ZERO, ZERO, ZERO };

		for (int i = k.bitLength() - 1; i >= 0; i--)
		{
			R = suma(R, R, ParametresCorba);
			if (k.testBit(i))
			{
				R = suma(R, P, ParametresCorba);
			}
		}

		return R;

	}

	/**
	 * 
	 * @param parametresECC
	 *            {n,Gx,Gy, a, b, p}, G = (Gx,Gy) punt d'ordre n de la corba y2
	 *            = x3 + ax + b mod p (evidentment, G no es el punt de
	 *            l'infinit);
	 * @return una llista {r, Px, Py}, r es la clau privada, i (Px, Py) punt
	 *         (diferent del punt de l'infinit) que es la clau publica.
	 */
	public static BigInteger[] clausECC(BigInteger[] parametresECC)
	{
		BigInteger p = parametresECC[5];
		BigInteger n = parametresECC[0];
		BigInteger r;

		BigInteger[] parametresCorba = new BigInteger[] { parametresECC[3],
				parametresECC[4], p };
		BigInteger[] G = new BigInteger[] { parametresECC[1], parametresECC[2],
				UNO };

		r = randomize(n);

		BigInteger[] P = multiple(r, G, parametresCorba);

		return new BigInteger[] { r, P[X], P[Y] };
	}

	/**
	 * 
	 * @param bytesAleatoris
	 * @param clauPrivadaECC
	 * @param clauPublicaECC
	 * @param parametresECC
	 *            {n,Gx,Gy, a, b, p}
	 * @return
	 */
	public static BigInteger ECCDHKT(byte[] bytesAleatoris,
			BigInteger clauPrivadaECC, BigInteger[] clauPublicaECC,
			BigInteger[] parametresECC)
	{

		BigInteger[] parametresCorba = new BigInteger[] { parametresECC[3],
				parametresECC[4], parametresECC[5] };
		BigInteger[] P = new BigInteger[] { clauPublicaECC[X],
				clauPublicaECC[Y], UNO };
		BigInteger[] DH = multiple(clauPrivadaECC, P, parametresCorba);

		byte dh[] = sacaSigno(DH[X]);

		byte result[] = new byte[dh.length + bytesAleatoris.length];
		System.arraycopy(bytesAleatoris, 0, result, 0, bytesAleatoris.length);
		System.arraycopy(dh, 0, result, bytesAleatoris.length, dh.length);

		return hash(result);
	}

	public static byte[] firmarECCDSA(byte[] M, BigInteger clauFirma,
			BigInteger[] parametresECC)
	{
		BigInteger[] parametresCorba = new BigInteger[] { parametresECC[3],
				parametresECC[4], parametresECC[5] };
		BigInteger n = parametresECC[0];
		BigInteger[] G = new BigInteger[] { parametresECC[1], parametresECC[2],
				UNO };

		BigInteger hM = hash(M);

		//Inicializacion dentro del bloque do - while
		BigInteger[] kG;
		BigInteger k;
		BigInteger f1;
		BigInteger f2;
		
		do
		{
			k = randomize(n);
			kG = multiple(k, G, parametresCorba);
			f1 = kG[X].mod(n);
			f2 = k.modInverse(n).multiply(hM.add(f1.multiply(clauFirma)))
					.mod(n);
		}
		while (f1.equals(ZERO) || f2.equals(ZERO));

		
		byte res[] = new byte[M.length + 64];
		System.arraycopy(M, 0, res, 0, M.length);

		byte f1Data[] = sacaSigno(f1);
		byte f2Data[] = sacaSigno(f2);

		System.arraycopy(padding(f1Data, 32), 0, res, M.length, 32);
		System.arraycopy(padding(f2Data, 32), 0, res, M.length + 32, 32);

		return res;

	}

	public static boolean verificarECCDSA(byte[] MS, BigInteger[] clauVer,
			BigInteger[] parametresECC)
	{
		BigInteger[] parametresCorba = new BigInteger[] { parametresECC[3],
				parametresECC[4], parametresECC[5] };
		BigInteger n = parametresECC[0];
		BigInteger[] P = new BigInteger[] { clauVer[X], clauVer[Y], UNO };
		BigInteger[] G = new BigInteger[] { parametresECC[1], parametresECC[2],
				UNO };

		byte[] M = Arrays.copyOfRange(MS, 0, MS.length - 64);
		BigInteger hM = hash(M);

		byte[] f1Data = Arrays.copyOfRange(MS, MS.length - 64, MS.length - 32);
		BigInteger f1 = byteArrayToBigInteger(f1Data);
		byte[] f2Data = Arrays.copyOfRange(MS, MS.length - 32, MS.length);
		BigInteger f2 = byteArrayToBigInteger(f2Data);

		BigInteger w1 = hM.multiply(f2.modInverse(n)).mod(n);
		BigInteger w2 = f1.multiply(f2.modInverse(n)).mod(n);
		BigInteger[] w1G = multiple(w1, G, parametresCorba);
		BigInteger[] w2P = multiple(w2, P, parametresCorba);
		BigInteger[] s = suma(w1G, w2P, parametresCorba);

		return s[X].mod(n).equals(f1);
	}

	private static boolean iguales(BigInteger[] P, BigInteger[] Q)
	{
		boolean zmatch = !(P[Z].equals(ZERO) ^ Q[Z].equals(ZERO));
		return P[X].equals(Q[X]) && P[Y].equals(Q[Y]) && zmatch;
	}

	private static BigInteger randomize(BigInteger max)
	{
		if(debugging) return runRandom;
		
		final BigInteger range = max.subtract(DOS);
		final int numBits = range.bitLength();
		BigInteger x = new BigInteger(numBits, sRandom);

		while (x.compareTo(range) >= 0);
		{
			x = new BigInteger(numBits, sRandom);
		}

		return x.add(UNO);
	}

	private static byte[] sacaSigno(BigInteger i)
	{
		byte[] b = i.toByteArray();
		if (b[0] == 0)
		{
			return Arrays.copyOfRange(b, 1, b.length);
		}
		else
		{
			return b;
		}
	}

	private static BigInteger hash(byte[] data)
	{
		if (debugging)
		{
			return runHash;
		}
		else
		{
			return sha256.hash(data);
		}
	}

	private static byte[] padding(byte[] a, int newLength)
	{
		final int length = a.length;
		if (length == newLength) return a;
		byte[] b = new byte[newLength];
		System.arraycopy(a, 0, b, newLength - length, length);
		return b;
	}

	private static BigInteger byteArrayToBigInteger(byte[] b)
	{
		if (b[0] == 0)
		{
			return new BigInteger(b);
		}
		else
		{
			return new BigInteger(padding(b, b.length + 1));
		}
	}
	
	static void clearRunMode()
	{
		debugging = false;
	}
	
	static void runMode(BigInteger hM, BigInteger R)
	{
		debugging = true;
		runHash = hM;
		runRandom = R;
	}
}
