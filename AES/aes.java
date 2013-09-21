import java.math.BigInteger;
import java.util.Random;
/**
 * 
 * @author Alberto Maldonado
 *
 */
class aes
{
	
	  //private final static byte logT[] = new byte[256]; 
	  //private final static byte invLogT[] = new byte[256]; 
	  //private final static byte Sbox[] = new byte[256]; 
	  //private final static byte invSbox[] = new byte[256]; 
	  //private final static byte rcon[] = new byte[16];
	 

	/**
	 * Al final he escogido no generar las tablas, aunque hay un static mas abajo de las tablas
	 * que las genera, buscando como generar las tablas de logaritmos di con una 
	 * web http://www.samiam.org/galois.html y explica paso a paso como generarlas y el algoritmo
	 * asi que en vez para coger la idea del algoritmo y generla, directamente copio la tabla. 
	 */
	
	private static byte Sbox[] = { (byte) 0x63, (byte) 0x7c, (byte) 0x77,
			(byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
			(byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe,
			(byte) 0xd7, (byte) 0xab, (byte) 0x76, (byte) 0xca, (byte) 0x82,
			(byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47,
			(byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf,
			(byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0, (byte) 0xb7,
			(byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f,
			(byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5,
			(byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
			(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18,
			(byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12,
			(byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2,
			(byte) 0x75, (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a,
			(byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52,
			(byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3,
			(byte) 0x2f, (byte) 0x84, (byte) 0x53, (byte) 0xd1, (byte) 0x00,
			(byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b,
			(byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a,
			(byte) 0x4c, (byte) 0x58, (byte) 0xcf, (byte) 0xd0, (byte) 0xef,
			(byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33,
			(byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f,
			(byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8, (byte) 0x51,
			(byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d,
			(byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda,
			(byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
			(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f,
			(byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7,
			(byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19,
			(byte) 0x73, (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc,
			(byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46,
			(byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e,
			(byte) 0x0b, (byte) 0xdb, (byte) 0xe0, (byte) 0x32, (byte) 0x3a,
			(byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c,
			(byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91,
			(byte) 0x95, (byte) 0xe4, (byte) 0x79, (byte) 0xe7, (byte) 0xc8,
			(byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e,
			(byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea,
			(byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08, (byte) 0xba,
			(byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6,
			(byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74,
			(byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
			(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48,
			(byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35,
			(byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d,
			(byte) 0x9e, (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11,
			(byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b,
			(byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55,
			(byte) 0x28, (byte) 0xdf, (byte) 0x8c, (byte) 0xa1, (byte) 0x89,
			(byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68,
			(byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0,
			(byte) 0x54, (byte) 0xbb, (byte) 0x16 };

	private static byte invSbox[] = { (byte) 0x52, (byte) 0x09, (byte) 0x6a,
			(byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38,
			(byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81,
			(byte) 0xf3, (byte) 0xd7, (byte) 0xfb, (byte) 0x7c, (byte) 0xe3,
			(byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff,
			(byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44,
			(byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb, (byte) 0x54,
			(byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2,
			(byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95,
			(byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e,
			(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28,
			(byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b,
			(byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1,
			(byte) 0x25, (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64,
			(byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4,
			(byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65,
			(byte) 0xb6, (byte) 0x92, (byte) 0x6c, (byte) 0x70, (byte) 0x48,
			(byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda,
			(byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7,
			(byte) 0x8d, (byte) 0x9d, (byte) 0x84, (byte) 0x90, (byte) 0xd8,
			(byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3,
			(byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05,
			(byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06, (byte) 0xd0,
			(byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f,
			(byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd,
			(byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b,
			(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f,
			(byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2,
			(byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6,
			(byte) 0x73, (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22,
			(byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2,
			(byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75,
			(byte) 0xdf, (byte) 0x6e, (byte) 0x47, (byte) 0xf1, (byte) 0x1a,
			(byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89,
			(byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa,
			(byte) 0x18, (byte) 0xbe, (byte) 0x1b, (byte) 0xfc, (byte) 0x56,
			(byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79,
			(byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe,
			(byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4, (byte) 0x1f,
			(byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07,
			(byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10,
			(byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f,
			(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19,
			(byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5,
			(byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c,
			(byte) 0xef, (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d,
			(byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8,
			(byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53,
			(byte) 0x99, (byte) 0x61, (byte) 0x17, (byte) 0x2b, (byte) 0x04,
			(byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26,
			(byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55,
			(byte) 0x21, (byte) 0x0c, (byte) 0x7d };

	private static byte rcon[] = { (byte) 0x8d, (byte) 0x01, (byte) 0x02,
			(byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40,
			(byte) 0x80, (byte) 0x1b, (byte) 0x36, (byte) 0x6c, (byte) 0xd8,
			(byte) 0xab, (byte) 0x4d, (byte) 0x9a };

	private static byte logT[] = { (byte) 0x00, (byte) 0xff, (byte) 0xc8,
			(byte) 0x08, (byte) 0x91, (byte) 0x10, (byte) 0xd0, (byte) 0x36,
			(byte) 0x5a, (byte) 0x3e, (byte) 0xd8, (byte) 0x43, (byte) 0x99,
			(byte) 0x77, (byte) 0xfe, (byte) 0x18, (byte) 0x23, (byte) 0x20,
			(byte) 0x07, (byte) 0x70, (byte) 0xa1, (byte) 0x6c, (byte) 0x0c,
			(byte) 0x7f, (byte) 0x62, (byte) 0x8b, (byte) 0x40, (byte) 0x46,
			(byte) 0xc7, (byte) 0x4b, (byte) 0xe0, (byte) 0x0e, (byte) 0xeb,
			(byte) 0x16, (byte) 0xe8, (byte) 0xad, (byte) 0xcf, (byte) 0xcd,
			(byte) 0x39, (byte) 0x53, (byte) 0x6a, (byte) 0x27, (byte) 0x35,
			(byte) 0x93, (byte) 0xd4, (byte) 0x4e, (byte) 0x48, (byte) 0xc3,
			(byte) 0x2b, (byte) 0x79, (byte) 0x54, (byte) 0x28, (byte) 0x09,
			(byte) 0x78, (byte) 0x0f, (byte) 0x21, (byte) 0x90, (byte) 0x87,
			(byte) 0x14, (byte) 0x2a, (byte) 0xa9, (byte) 0x9c, (byte) 0xd6,
			(byte) 0x74, (byte) 0xb4, (byte) 0x7c, (byte) 0xde, (byte) 0xed,
			(byte) 0xb1, (byte) 0x86, (byte) 0x76, (byte) 0xa4, (byte) 0x98,
			(byte) 0xe2, (byte) 0x96, (byte) 0x8f, (byte) 0x02, (byte) 0x32,
			(byte) 0x1c, (byte) 0xc1, (byte) 0x33, (byte) 0xee, (byte) 0xef,
			(byte) 0x81, (byte) 0xfd, (byte) 0x30, (byte) 0x5c, (byte) 0x13,
			(byte) 0x9d, (byte) 0x29, (byte) 0x17, (byte) 0xc4, (byte) 0x11,
			(byte) 0x44, (byte) 0x8c, (byte) 0x80, (byte) 0xf3, (byte) 0x73,
			(byte) 0x42, (byte) 0x1e, (byte) 0x1d, (byte) 0xb5, (byte) 0xf0,
			(byte) 0x12, (byte) 0xd1, (byte) 0x5b, (byte) 0x41, (byte) 0xa2,
			(byte) 0xd7, (byte) 0x2c, (byte) 0xe9, (byte) 0xd5, (byte) 0x59,
			(byte) 0xcb, (byte) 0x50, (byte) 0xa8, (byte) 0xdc, (byte) 0xfc,
			(byte) 0xf2, (byte) 0x56, (byte) 0x72, (byte) 0xa6, (byte) 0x65,
			(byte) 0x2f, (byte) 0x9f, (byte) 0x9b, (byte) 0x3d, (byte) 0xba,
			(byte) 0x7d, (byte) 0xc2, (byte) 0x45, (byte) 0x82, (byte) 0xa7,
			(byte) 0x57, (byte) 0xb6, (byte) 0xa3, (byte) 0x7a, (byte) 0x75,
			(byte) 0x4f, (byte) 0xae, (byte) 0x3f, (byte) 0x37, (byte) 0x6d,
			(byte) 0x47, (byte) 0x61, (byte) 0xbe, (byte) 0xab, (byte) 0xd3,
			(byte) 0x5f, (byte) 0xb0, (byte) 0x58, (byte) 0xaf, (byte) 0xca,
			(byte) 0x5e, (byte) 0xfa, (byte) 0x85, (byte) 0xe4, (byte) 0x4d,
			(byte) 0x8a, (byte) 0x05, (byte) 0xfb, (byte) 0x60, (byte) 0xb7,
			(byte) 0x7b, (byte) 0xb8, (byte) 0x26, (byte) 0x4a, (byte) 0x67,
			(byte) 0xc6, (byte) 0x1a, (byte) 0xf8, (byte) 0x69, (byte) 0x25,
			(byte) 0xb3, (byte) 0xdb, (byte) 0xbd, (byte) 0x66, (byte) 0xdd,
			(byte) 0xf1, (byte) 0xd2, (byte) 0xdf, (byte) 0x03, (byte) 0x8d,
			(byte) 0x34, (byte) 0xd9, (byte) 0x92, (byte) 0x0d, (byte) 0x63,
			(byte) 0x55, (byte) 0xaa, (byte) 0x49, (byte) 0xec, (byte) 0xbc,
			(byte) 0x95, (byte) 0x3c, (byte) 0x84, (byte) 0x0b, (byte) 0xf5,
			(byte) 0xe6, (byte) 0xe7, (byte) 0xe5, (byte) 0xac, (byte) 0x7e,
			(byte) 0x6e, (byte) 0xb9, (byte) 0xf9, (byte) 0xda, (byte) 0x8e,
			(byte) 0x9a, (byte) 0xc9, (byte) 0x24, (byte) 0xe1, (byte) 0x0a,
			(byte) 0x15, (byte) 0x6b, (byte) 0x3a, (byte) 0xa0, (byte) 0x51,
			(byte) 0xf4, (byte) 0xea, (byte) 0xb2, (byte) 0x97, (byte) 0x9e,
			(byte) 0x5d, (byte) 0x22, (byte) 0x88, (byte) 0x94, (byte) 0xce,
			(byte) 0x19, (byte) 0x01, (byte) 0x71, (byte) 0x4c, (byte) 0xa5,
			(byte) 0xe3, (byte) 0xc5, (byte) 0x31, (byte) 0xbb, (byte) 0xcc,
			(byte) 0x1f, (byte) 0x2d, (byte) 0x3b, (byte) 0x52, (byte) 0x6f,
			(byte) 0xf6, (byte) 0x2e, (byte) 0x89, (byte) 0xf7, (byte) 0xc0,
			(byte) 0x68, (byte) 0x1b, (byte) 0x64, (byte) 0x04, (byte) 0x06,
			(byte) 0xbf, (byte) 0x83, (byte) 0x38 };

	private static byte invLogT[] = { (byte) 0x01, (byte) 0xe5, (byte) 0x4c,
			(byte) 0xb5, (byte) 0xfb, (byte) 0x9f, (byte) 0xfc, (byte) 0x12,
			(byte) 0x03, (byte) 0x34, (byte) 0xd4, (byte) 0xc4, (byte) 0x16,
			(byte) 0xba, (byte) 0x1f, (byte) 0x36, (byte) 0x05, (byte) 0x5c,
			(byte) 0x67, (byte) 0x57, (byte) 0x3a, (byte) 0xd5, (byte) 0x21,
			(byte) 0x5a, (byte) 0x0f, (byte) 0xe4, (byte) 0xa9, (byte) 0xf9,
			(byte) 0x4e, (byte) 0x64, (byte) 0x63, (byte) 0xee, (byte) 0x11,
			(byte) 0x37, (byte) 0xe0, (byte) 0x10, (byte) 0xd2, (byte) 0xac,
			(byte) 0xa5, (byte) 0x29, (byte) 0x33, (byte) 0x59, (byte) 0x3b,
			(byte) 0x30, (byte) 0x6d, (byte) 0xef, (byte) 0xf4, (byte) 0x7b,
			(byte) 0x55, (byte) 0xeb, (byte) 0x4d, (byte) 0x50, (byte) 0xb7,
			(byte) 0x2a, (byte) 0x07, (byte) 0x8d, (byte) 0xff, (byte) 0x26,
			(byte) 0xd7, (byte) 0xf0, (byte) 0xc2, (byte) 0x7e, (byte) 0x09,
			(byte) 0x8c, (byte) 0x1a, (byte) 0x6a, (byte) 0x62, (byte) 0x0b,
			(byte) 0x5d, (byte) 0x82, (byte) 0x1b, (byte) 0x8f, (byte) 0x2e,
			(byte) 0xbe, (byte) 0xa6, (byte) 0x1d, (byte) 0xe7, (byte) 0x9d,
			(byte) 0x2d, (byte) 0x8a, (byte) 0x72, (byte) 0xd9, (byte) 0xf1,
			(byte) 0x27, (byte) 0x32, (byte) 0xbc, (byte) 0x77, (byte) 0x85,
			(byte) 0x96, (byte) 0x70, (byte) 0x08, (byte) 0x69, (byte) 0x56,
			(byte) 0xdf, (byte) 0x99, (byte) 0x94, (byte) 0xa1, (byte) 0x90,
			(byte) 0x18, (byte) 0xbb, (byte) 0xfa, (byte) 0x7a, (byte) 0xb0,
			(byte) 0xa7, (byte) 0xf8, (byte) 0xab, (byte) 0x28, (byte) 0xd6,
			(byte) 0x15, (byte) 0x8e, (byte) 0xcb, (byte) 0xf2, (byte) 0x13,
			(byte) 0xe6, (byte) 0x78, (byte) 0x61, (byte) 0x3f, (byte) 0x89,
			(byte) 0x46, (byte) 0x0d, (byte) 0x35, (byte) 0x31, (byte) 0x88,
			(byte) 0xa3, (byte) 0x41, (byte) 0x80, (byte) 0xca, (byte) 0x17,
			(byte) 0x5f, (byte) 0x53, (byte) 0x83, (byte) 0xfe, (byte) 0xc3,
			(byte) 0x9b, (byte) 0x45, (byte) 0x39, (byte) 0xe1, (byte) 0xf5,
			(byte) 0x9e, (byte) 0x19, (byte) 0x5e, (byte) 0xb6, (byte) 0xcf,
			(byte) 0x4b, (byte) 0x38, (byte) 0x04, (byte) 0xb9, (byte) 0x2b,
			(byte) 0xe2, (byte) 0xc1, (byte) 0x4a, (byte) 0xdd, (byte) 0x48,
			(byte) 0x0c, (byte) 0xd0, (byte) 0x7d, (byte) 0x3d, (byte) 0x58,
			(byte) 0xde, (byte) 0x7c, (byte) 0xd8, (byte) 0x14, (byte) 0x6b,
			(byte) 0x87, (byte) 0x47, (byte) 0xe8, (byte) 0x79, (byte) 0x84,
			(byte) 0x73, (byte) 0x3c, (byte) 0xbd, (byte) 0x92, (byte) 0xc9,
			(byte) 0x23, (byte) 0x8b, (byte) 0x97, (byte) 0x95, (byte) 0x44,
			(byte) 0xdc, (byte) 0xad, (byte) 0x40, (byte) 0x65, (byte) 0x86,
			(byte) 0xa2, (byte) 0xa4, (byte) 0xcc, (byte) 0x7f, (byte) 0xec,
			(byte) 0xc0, (byte) 0xaf, (byte) 0x91, (byte) 0xfd, (byte) 0xf7,
			(byte) 0x4f, (byte) 0x81, (byte) 0x2f, (byte) 0x5b, (byte) 0xea,
			(byte) 0xa8, (byte) 0x1c, (byte) 0x02, (byte) 0xd1, (byte) 0x98,
			(byte) 0x71, (byte) 0xed, (byte) 0x25, (byte) 0xe3, (byte) 0x24,
			(byte) 0x06, (byte) 0x68, (byte) 0xb3, (byte) 0x93, (byte) 0x2c,
			(byte) 0x6f, (byte) 0x3e, (byte) 0x6c, (byte) 0x0a, (byte) 0xb8,
			(byte) 0xce, (byte) 0xae, (byte) 0x74, (byte) 0xb1, (byte) 0x42,
			(byte) 0xb4, (byte) 0x1e, (byte) 0xd3, (byte) 0x49, (byte) 0xe9,
			(byte) 0x9c, (byte) 0xc8, (byte) 0xc6, (byte) 0xc7, (byte) 0x22,
			(byte) 0x6e, (byte) 0xdb, (byte) 0x20, (byte) 0xbf, (byte) 0x43,
			(byte) 0x51, (byte) 0x52, (byte) 0x66, (byte) 0xb2, (byte) 0x76,
			(byte) 0x60, (byte) 0xda, (byte) 0xc5, (byte) 0xf3, (byte) 0xf6,
			(byte) 0xaa, (byte) 0xcd, (byte) 0x9a, (byte) 0xa0, (byte) 0x75,
			(byte) 0x54, (byte) 0x0e, (byte) 0x01 };

	/*private static byte rotRB(byte b, int n)
	{
		int v = b & 0xFF;
		v = (v >>> n) | (v << (8 - n));
		return (byte) (v & 0xFF);
	}

	private static byte byteInv(int i)
	{
		if (i == 0) return 0;
		i = logT[i] & 0xFF;
		return invLogT[255 - i];
	}*/

	private static byte byteMul(int x, int y)
	{
		if (x == 0 || y == 0) return 0;
		x = logT[x & 0xFF] & 0xFF;
		y = logT[y & 0xFF] & 0xFF;
		return invLogT[(x + y) % 255];
	}

	/*static
	{
		logT[1] = 0;
		invLogT[0] = 1;
		logT[3] = 1;
		invLogT[1] = 3;
		for (int i = 2; i < 256; i++)
		{
			int val = invLogT[i - 1] & 0xFF;
			val = (val << 1) ^ val;
			if ((val & 0x100) == 0x100)
			{
				val = (val ^ 0x1B) & 0xFF;
			}
			invLogT[i] = (byte) val;
			logT[val] = (byte) i;
		}
		
		for (int i = 0; i < 256; i++)
		{
			byte val = (byte) i;

			val = byteInv(i);
			val = (byte) (val ^ rotRB(val, 4) ^ rotRB(val, 5) ^ rotRB(val, 6) ^ rotRB(
					val, 7));

			val ^= 0x63;
			Sbox[i] = val;
			invSbox[val & 0xFF] = (byte) i;
		}

		rcon[0] = byteInv(1);
		rcon[1] = 1;
		for (int i = 2; i < 16; i++)
		{
			rcon[i] = byteMul(rcon[i - 1], 2);
		}
	}*/
	
	/**
	 * 
	 * @param M
	 *            es una llista de bytes que representa el missatge a xifrar
	 * @param K
	 *            es un enter que representa la clau
	 * @param Lk
	 *            es la longitud de la clau (128, 192 o 256)
	 * @return llista de bytes que es el criptograma obtingut xifrant el
	 *         missatge M (despres d'afegir-li el padding) en mode CBC amb la
	 *         clau K
	 */
	public static byte[] xifrarAES(byte[] M, BigInteger K, int Lk)
	{
		final int Nk = Lk / 32;
		final int Nr = 6 + Nk;
		final byte[][][] W = keyExpansion(K, Nk, Nr);
		byte m[] = padding(M);
		int veces = (m.length / 16);
		/*
		 * El mensaje codificado sera de tamano de m (el mesaje despues del
		 * padding) + 16 que corresponden al vector de inicializacion del modo
		 * CBC
		 */
		byte[] result = new byte[m.length + 4 * 4];

		/*
		 * parcial ira acumulando el resultado de rijndael y tendra la misma
		 * longitud que el mensaje con padding
		 */
		byte[] parcial = new byte[m.length];
		byte[][] bloque = new byte[4][4];

		// Bloque inicial aleatorio
		byte[][] iv = new byte[4][4];
		final Random rnd = new Random();
		for (int i = 0; i < 4; i++)
		{
			rnd.nextBytes(iv[i]);
		}

		/*
		 * Escribimos al principio de resultado el iv, que necesitaremos despues
		 * en el descifrado
		 */
		accumRij(iv, result, 0);

		// por no estar trabajando con iv todo el rato
		byte[][] estat = iv.clone();

		for (int i = 0; i < veces; i++)
		{
			byteArrayToMatrix(m, bloque, i);
			matrixXor(estat, bloque);
			estat = rijndael(estat, W, Nk, Nr);
			accumRij(estat, parcial, i);
		}

		System.arraycopy(parcial, 0, result, 16, parcial.length);

		return result;
	}

	/*
	 * Funcion identica a la de xifrarAES solo que a esta se le puede poner un
	 * bloque inicial de CBC sin ser generado
	 */
	public static byte[] xifrarAESCBC(byte[] M, BigInteger K, int Lk,
			byte[][] iv)
	{
		final int Nk = Lk / 32;
		final int Nr = 6 + Nk;
		final byte[][][] W = keyExpansion(K, Nk, Nr);
		byte m[] = padding(M);
		int veces = (m.length / 16);
		/*
		 * El mensaje codificado sera de tamano de m (el mesaje despues del
		 * padding) + 16 que corresponden al vector de inicializacion del modo
		 * CBC
		 */
		byte[] result = new byte[m.length + 4 * 4];

		/*
		 * parcial ira acumulando el resultado de rijndael y tendra la misma
		 * longitud que el mensaje con padding
		 */
		byte[] parcial = new byte[m.length];
		byte[][] bloque = new byte[4][4];

		/*
		 * Escribimos al principio de resultado el iv, que necesitaremos despues
		 * en el descifrado
		 */
		accumRij(iv, result, 0);

		// por no estar trabajando con iv todo el rato
		byte[][] estat = iv.clone();

		for (int i = 0; i < veces; i++)
		{
			byteArrayToMatrix(m, bloque, i);
			matrixXor(estat, bloque);
			estat = rijndael(estat, W, Nk, Nr);
			accumRij(estat, parcial, i);
		}

		System.arraycopy(parcial, 0, result, 16, parcial.length);

		return result;
	}

	/**
	 * 
	 * @param K
	 *            es un enter que representa la clau
	 * @param Nk
	 *            es el nombre de columnes de la clau
	 * @param Nr
	 *            es el nombre de tombs
	 * @return llista de les Nr + 1 subclaus per al xifrat, el primer index fa
	 *         referencia a la subclau, el segon a les files de la subclau i el
	 *         darrer a les columnes de la subclau
	 */
	public static byte[][][] keyExpansion(BigInteger K, int Nk, int Nr)
	{
		byte W[][][] = new byte[Nr + 1][4][4];
		byte[] tmp = new byte[5];
		byte kori[] = K.toByteArray();
		byte k[] = new byte[Nk * 4];
		if (kori.length >= k.length)
		{
			System.arraycopy(kori, kori.length - k.length, k, 0, k.length);
		}
		else
		{
			System.arraycopy(kori, 0, k, k.length - kori.length, kori.length);
		}

		/*
		 * La clau K es disposara en forma de bits en una matriu de 4 files per
		 * Nk columnes. Les COLUMNES les denotarem per clau(0); clau(1); ...;
		 * clau(Nk -1).
		 */
		for (int i = 0; i < Nk; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				W[i / 4][j][i % 4] = k[i * 4 + j];
			}
		}

		for (int i = Nk; i < 4 * (Nr + 1); i++)
		{
			for (int j = 0; j < 4; j++)
			{
				tmp[j] = W[(i - 1) / 4][j][(i - 1) % 4];
			}

			if (i % Nk == 0)
			{
				tmp[4] = tmp[0];
				byte tt;
				for (int j = 0; j < 4; j++)
				{
					if (j == 3)
					{
						tt = tmp[4];
					}
					else
					{
						tt = tmp[j + 1];
					}

					if (j == 0)
					{
						tmp[j] = (byte) (byteSub(tt) ^ rcon[i / Nk]);
					}
					else
					{
						tmp[j] = (byte) (byteSub(tt));
					}
				}

			}
			else if (Nk > 6 && i % Nk == 4)
			{
				for (int j = 0; j < 4; j++)
				{
					tmp[j] = (byte) (byteSub(tmp[j]));
				}
			}

			for (int j = 0; j < 4; j++)
			{
				W[i / 4][j][i % 4] = (byte) (W[(i - Nk) / 4][j][(i - Nk) % 4] ^ tmp[j]);
			}
		}

		return W;
	}

	public static byte[][][] invKeyExpansion(BigInteger K, int Nk, int Nr)
	{
		byte invK[][][] = keyExpansion(K, Nk, Nr);

		for (int i = 1; i < invK.length - 1; i++)
		{
			invK[i] = invMixColumn(invK[i]);
		}

		return invK;
	}

	public static byte byteSub(byte subestat)
	{
		return Sbox[subestat & 0xFF];
	}

	private static byte[][] byteSub(byte[][] estat)
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				estat[i][j] = byteSub(estat[i][j]);
			}
		}

		return estat;
	}

	public static byte invByteSub(byte subestat)
	{
		return invSbox[subestat & 0xFF];
	}

	private static byte[][] invByteSub(byte[][] estat)
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				estat[i][j] = invByteSub(estat[i][j]);
			}
		}

		return estat;
	}

	public static byte[][] shiftRow(byte[][] estat)
	{
		for (int i = 0; i < 4; i++)
		{
			byte[] tmp = estat[i].clone();

			for (int j = 0; j < 4; j++)
			{
				estat[i][j] = tmp[(j + i) % 4];
			}
		}

		return estat;
	}

	public static byte[][] invShiftRow(byte[][] estat)
	{
		for (int i = 0; i < 4; i++)
		{
			byte[] tmp = estat[i].clone();

			for (int j = 0; j < 4; j++)
			{
				int x = j - i;
				if (x < 0)
				{
					x += 4;
				}
				estat[i][j] = tmp[x];
			}
		}

		return estat;
	}

	public static byte[][] mixColumn(byte[][] estat)
	{
		byte[] t = new byte[4];

		for (int j = 0; j < 4; j++)
		{
			for (int i = 0; i < 4; i++)
			{
				t[i] = estat[i][j];
			}

			estat[0][j] = (byte) (byteMul(2, t[0]) ^ byteMul(3, t[1]) ^ t[2] ^ t[3]);
			estat[1][j] = (byte) (t[0] ^ byteMul(2, t[1]) ^ byteMul(3, t[2]) ^ t[3]);
			estat[2][j] = (byte) (t[0] ^ t[1] ^ byteMul(2, t[2]) ^ byteMul(3,
					t[3]));
			estat[3][j] = (byte) (byteMul(3, t[0]) ^ t[1] ^ t[2] ^ byteMul(2,
					t[3]));
		}

		return estat;
	}

	public static byte[][] invMixColumn(byte[][] estat)
	{
		byte[] t = new byte[4];

		for (int j = 0; j < 4; j++)
		{
			for (int i = 0; i < 4; i++)
			{
				t[i] = estat[i][j];
			}

			estat[0][j] = (byte) (byteMul(14, t[0]) ^ byteMul(11, t[1])
					^ byteMul(13, t[2]) ^ byteMul(9, t[3]));
			estat[1][j] = (byte) (byteMul(9, t[0]) ^ byteMul(14, t[1])
					^ byteMul(11, t[2]) ^ byteMul(13, t[3]));
			estat[2][j] = (byte) (byteMul(13, t[0]) ^ byteMul(9, t[1])
					^ byteMul(14, t[2]) ^ byteMul(11, t[3]));
			estat[3][j] = (byte) (byteMul(11, t[0]) ^ byteMul(13, t[1])
					^ byteMul(9, t[2]) ^ byteMul(14, t[3]));
		}

		return estat;
	}

	/**
	 * 
	 * @param estat
	 *            matriu 4x4 tals que els seus elements son bytes
	 * @param Ki
	 *            matriu 4x4 tals que els seus elements son bytes
	 * @return una matriu de 4x4, resultat de sumar les matrius estat i Ki bit a
	 *         bit.
	 */
	public static byte[][] addRoundKey(byte[][] estat, byte[][] Ki)
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				estat[i][j] ^= Ki[i][j];
			}
		}

		return estat;
	}

	/**
	 * 
	 * @param estat
	 *            es una matriu de 4x4, els elements de la qual son bytes
	 * @param W
	 *            es la matriu que emmagatzema les subclaus
	 * @param Nk
	 *            es la longitud de la clau partit per 32
	 * @param Nr
	 *            es el nombre de tombs
	 * @return
	 */
	public static byte[][] rijndael(byte[][] estat, byte[][][] W, int Nk, int Nr)
	{
		estat = addRoundKey(estat, W[0]);

		for (int i = 1; i < Nr; i++)
		{
			estat = byteSub(estat);
			estat = shiftRow(estat);
			estat = mixColumn(estat);
			estat = addRoundKey(estat, W[i]);
		}

		estat = byteSub(estat);
		estat = shiftRow(estat);
		estat = addRoundKey(estat, W[Nr]);

		return estat;
	}

	public static byte[][] invRijndael(byte[][] estat, byte[][][] InvW, int Nk,
			int Nr)
	{
		estat = addRoundKey(estat, InvW[Nr]);
		for (int i = Nr - 1; i > 0; i--)
		{
			estat = invByteSub(estat);
			estat = invShiftRow(estat);
			estat = invMixColumn(estat);
			estat = addRoundKey(estat, InvW[i]);
		}
		estat = invByteSub(estat);
		estat = invShiftRow(estat);
		estat = addRoundKey(estat, InvW[0]);

		return estat;
	}

	private static void byteArrayToMatrix(byte[] ba, byte[][] m, int w)
	{
		int off = w * 16;

		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				m[i][j] = ba[off + i + (j * 4)];
			}
		}
	}

	private static void accumRij(byte[][] m, byte[] ba, int w)
	{
		int off = w * 16;
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				ba[off + i + (j * 4)] = m[i][j];
			}
		}
	}

	private static byte[][] matrixXor(byte[][] x, final byte[][] y)
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				x[i][j] ^= y[i][j];
			}
		}

		return x;

	}

	/**
	 * Padding de M sigue la misma estrategia que el padding realizado para
	 * SHA-256, aunque esta vez para 128 bits en vez de 512.
	 * 
	 */
	private static byte[] padding(byte[] M)
	{
		long l = M.length * 8;

		long k = (128 - (l + 1 + 64)) % 128;

		k = (k < 0) ? k + 128 : k;

		int len = (int) (((l + 1 + k) / 8) + 8);

		byte[] pad = new byte[len];

		System.arraycopy(M, 0, pad, 0, M.length);

		pad[M.length] = (byte) 0x80;

		int bytpad = pad.length - 8;

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

	private static byte[] unpadding(byte[] result)
	{
		/*
		 * off nos dira donde empezar a mirar el byte al que accedemos al
		 * principio sera el byte de mayor peso
		 */
		int off = result.length - 8;

		long l = 0;

		l = (result[off++] & 0xFF) << 56;
		l |= (result[off++] & 0xFF) << 48;
		l |= (result[off++] & 0xFF) << 40;
		l |= (result[off++] & 0xFF) << 32;
		l |= (result[off++] & 0xFF) << 24;
		l |= (result[off++] & 0xFF) << 16;
		l |= (result[off++] & 0xFF) << 8;
		l |= (result[off] & 0xFF);

		int len = (int) (l / 8);
		byte[] res = new byte[len];
		System.arraycopy(result, 0, res, 0, len);

		return res;
	}

	public static byte[] desxifrarAES(byte[] C, BigInteger K, int Lk)
	{
		int Nk = Lk / 32;
		int Nr = 6 + Nk;
		byte[][][] W = invKeyExpansion(K, Nk, Nr);
		int veces = (C.length / 16);
		/*
		 * Ahora result sera de tamano de C - 16 bytes del vector del CBC
		 */
		byte[] result = new byte[C.length - 4 * 4];

		byte[][] estat = new byte[4][4];
		byte[][] iv = new byte[4][4];
		byteArrayToMatrix(C, iv, 0);
		byte[][] y = iv.clone();

		for (int i = 1; i < veces; i++)
		{
			byteArrayToMatrix(C, estat, i);
			estat = invRijndael(estat, W, Nk, Nr);
			matrixXor(estat, y);
			accumRij(estat, result, i - 1);

			byteArrayToMatrix(C, y, i);
		}

		return unpadding(result);
	}
}