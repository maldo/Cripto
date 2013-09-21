import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class run
{
	static final String AZ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static final String HEXES = "0123456789ABCDEF";

	static Random r = new Random();

	public static void main(String[] args) throws NoSuchAlgorithmException
	{
		int total = r.nextInt(5000);

		System.out
				.println("Se van a ejecutar "
						+ total
						+ " pruebas contra el SHA256 implementado en las librerias de java");

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		for (int i = 1; i < total + 1; i++)
		{
			String sgen = rndString(r.nextInt(i));

			byte[] gen = sgen.getBytes();

			String jsha = getHex(md.digest(gen));

			String mysha = getHex(sha256.test(gen));
			
			System.out.println("Entrada: "+ sgen);

			System.out.println("JAVA SHA256: " + jsha);
			System.out.println("SHA256_____: " + mysha);
			System.out.println();
			
			if (!jsha.equals(mysha))
			{
				System.out.println("FALLO con la entrada #" + i);

				System.out.println("Se sale del Test, quedan por hacer "
						+ (total - i) + " pruebas");
				return;
			}
		}
		System.out.println("Se ha ejecutado correctamente " + total + " veces");
	}

	private static String rndString(int length)
	{
		StringBuffer sb = new StringBuffer();
		for (int i = length; i > 0; i--)
		{
			sb.append(AZ.charAt(r.nextInt(AZ.length())));
		}
		return sb.toString();
	}

	private static String getHex(byte[] raw)
	{
		if (raw == null)
		{
			return null;
		}

		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for (final byte b : raw)
		{
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(
					HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

}
