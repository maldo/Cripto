import java.math.BigInteger;

public class sha256
{
	private static boolean DEBUG = false;

	private static int[] h = new int[8];

	private static int[] W = new int[64];

	private static int cont;

	private static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf,
			0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
			0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
			0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
			0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
			0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
			0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
			0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
			0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
			0xc67178f2 };

	public static BigInteger hash(byte[] M)
	{
		ini();

		cont = 0;

		byte[] pad = padding(M);

		cal(pad);

		if (DEBUG)
		{
			System.out.println();
			System.out.print("Resultado final");
			print(h);
			System.out.println();
		}

		return intArray2BigInt(h);
	}

	private static void ini()
	{
		h[0] = 0x6a09e667;
		h[1] = 0xbb67ae85;
		h[2] = 0x3c6ef372;
		h[3] = 0xa54ff53a;
		h[4] = 0x510e527f;
		h[5] = 0x9b05688c;
		h[6] = 0x1f83d9ab;
		h[7] = 0x5be0cd19;
	}

	private static byte[] padding(byte[] M)
	{
		long l = M.length * 8;
		// longitud de M en bits

		long k = (512 - (l + 1 + 64)) % 512;
		k = (k < 0) ? k + 512 : k;
		// k zeros de padding

		int len = (int) ((l + 1 + k) / 8) + 8;
		// longitud del nuevo vector de padding mensaje original + 1 bit + k
		// bits + 64 bits, aunque en bytes

		byte[] pad = new byte[len];
		// el contenido inicializado de pad es todo 0s, con lo que ya tenemos
		// puestos los k zeros de padding

		System.arraycopy(M, 0, pad, 0, M.length);
		// Copiamos en vector orginal al nuevo vector de padding

		pad[M.length] = (byte) 0x80;
		// ponemos en 1

		int bytpad = pad.length - 8;
		// Ponemos la longtitud del mensaje original en los ultimos 64 bits.
		pad[bytpad++] = (byte) (l >>> 56);
		pad[bytpad++] = (byte) (l >>> 48);
		pad[bytpad++] = (byte) (l >>> 40);
		pad[bytpad++] = (byte) (l >>> 32);
		pad[bytpad++] = (byte) (l >>> 24);
		pad[bytpad++] = (byte) (l >>> 16);
		pad[bytpad++] = (byte) (l >>> 8);
		pad[bytpad] = (byte) (l);

		return pad;
	}

	private static void cal(byte[] pad)
	{
		int veces = pad.length / 64;

		for (int x = 0; x < veces; x++)
		{
			for (int r = 0; r < 16; ++r)
			{
				W[r] = words(pad);
			}

			for (int r = 16; r < 64; ++r)
			{
				W[r] = delta1(W[r - 2]) + W[r - 7] + delta0(W[r - 15])
						+ W[r - 16];
			}

			int A = h[0];
			int B = h[1];
			int C = h[2];
			int D = h[3];
			int E = h[4];
			int F = h[5];
			int G = h[6];
			int H = h[7];
			int T1, T2;

			for (int i = 0; i < 64; ++i)
			{
				T1 = H + sigma1(E) + Ch(E, F, G) + K[i] + W[i];
				T2 = sigma0(A) + Maj(A, B, C);
				H = G;
				G = F;
				F = E;
				E = D + T1;
				D = C;
				C = B;
				B = A;
				A = T1 + T2;

				if (DEBUG)
				{
					printpar(i, A, B, C, D, E, F, G, H);
				}

			}

			if (DEBUG)
			{
				System.out.println();
				System.out.println();
				System.out.print("Resultado parcial antes de la vuelta " + x);
				print(h);
			}

			h[0] += A;
			h[1] += B;
			h[2] += C;
			h[3] += D;
			h[4] += E;
			h[5] += F;
			h[6] += G;
			h[7] += H;

			if (DEBUG)
			{
				System.out.println();
				System.out.print("Resultado parcial de la vuelta " + x);
				print(h);
			}
		}

	}

	private static int words(byte[] b)
	{
		return b[cont++] << 24 | (b[cont++] & 0xFF) << 16
				| (b[cont++] & 0xFF) << 8 | (b[cont++] & 0xFF);
	}

	private static int delta1(int X)
	{
		return RotR(X, 17) ^ RotR(X, 19) ^ ShR(X, 10);
	}

	private static int delta0(int X)
	{
		return RotR(X, 7) ^ RotR(X, 18) ^ ShR(X, 3);
	}

	private static int Maj(int x, int y, int z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	private static int Ch(int x, int y, int z)
	{
		return (x & y) ^ (~x & z);
	}

	private static int sigma0(int x)
	{
		return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
	}

	private static int sigma1(int x)
	{
		return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
	}

	private static int ShR(int x, int i)
	{
		return x >>> i;
	}

	private static int RotR(int x, int i)
	{
		return (x >>> i) | (x << (32 - i));
	}

	/*----- Auxiliares y funciones de testing -----*/

	private static BigInteger intArray2BigInt(int[] h)
	{
		byte[] r = new byte[1 + h.length * 4];
		// Para que sea un BigInteger positivo tendra una poscion 0 por delante

		for (int i = 0; i < h.length; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				r[1 + i * 4 + j] = (byte) (h[i] >> (32 - (j + 1) * 8));
			}
		}

		return new BigInteger(r);
	}

	public static byte[] test(byte[] M)
	{
		ini();

		cont = 0;

		byte[] pad = padding(M);

		cal(pad);

		return intArray2ByteArray(h);
	}

	private static byte[] intArray2ByteArray(int[] a)
	{
		byte[] b = new byte[a.length * 4];

		for (int i = 0; i < a.length; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				b[i * 4 + j] = (byte) (a[i] >> (32 - (j + 1) * 8));
			}
		}

		return b;
	}

	private static void print(int[] b)
	{
		System.out.println();
		System.out.print(Integer.toHexString(b[0]) + " ");
		System.out.print(Integer.toHexString(b[1]) + " ");
		System.out.print(Integer.toHexString(b[2]) + " ");
		System.out.print(Integer.toHexString(b[3]) + " ");
		System.out.print(Integer.toHexString(b[4]) + " ");
		System.out.print(Integer.toHexString(b[5]) + " ");
		System.out.print(Integer.toHexString(b[6]) + " ");
		System.out.print(Integer.toHexString(b[7]) + " ");
		System.out.println();
	}

	private static void printpar(int i, int A, int B, int C, int D, int E,
			int F, int G, int H)
	{
		System.out.println();
		System.out.print("t = " + i + " : ");
		System.out.print(Integer.toHexString(A) + " ");
		System.out.print(Integer.toHexString(B) + " ");
		System.out.print(Integer.toHexString(C) + " ");
		System.out.print(Integer.toHexString(D) + " ");
		System.out.print(Integer.toHexString(E) + " ");
		System.out.print(Integer.toHexString(F) + " ");
		System.out.print(Integer.toHexString(G) + " ");
		System.out.print(Integer.toHexString(H) + " ");
	}

}
