
/**
 * @author Rafael Marcén Altarriba (650435)
 * 			
 * @version 1.0
 * @date 26-12-2015
 *
 * HASH
 * ------------------------------------------------------------------
 * Se ha utilizado el algoritmo SHA-512 que puede calcular un hash
 * para 2^64 - 1 bits y que consiste en 64 rondas de hashing. 
 * El tamaño de la clave es 512 bits (64 bytes).
 * Los motivos de esta decisión son:
 * 	- Es uno de los algoritmos más seguros, sin vulnerabilidades 
 *    conocidas.
 * 	- El calculo del hash no es demasiado costoso en las computadoras
 * 	  actuales.
 *
 *
 * GENERACION DE CLAVE PUBLICA 
 * ------------------------------------------------------------------
 * Se ha utilizado RSA/ECB/PCKS5Padding (algoritmo RSA, en modo 
 * Electronic Code Book, con relleno PCKS1).
 * Los tamaños de los pares de claves generadas son 512, 1024 y 2048 
 * bits.
 * Los motivos de esta decisión son:
 * - Para un sistema actual, un par de claves de 512 bits es lo 
 *   minimo aceptable ya que romper RSA consiste en resolver un
 *   problema de factorizacion de primos que se alarga segun el 
 *   tamaño de la clave.
 * 
 * 
 * GENERACION DE CLAVE SECRETA
 * Se ha utilizado AES.
 * Los tamaños de las claves generadas son 128, 192 y 256 bits.
 * Para poder utilizar AES con tamaños de clave mayores que 128
 * bits hay que utilizar JCE Unlimited Strength Jurisdiction Policy
 * Files.
 * Fuente: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 * Los motivos de esta decisión son:
 * - En la criptografia de clave secreta o simetrica una clave de 
 *   128 bits es segura para los sistema actuales ya que romper
 *   el sistema no consiste en resolver un problema matematico como
 *   en la criptografica de clave publica, las claves son secretas.
 * 
 * 
 * CIFRADO Y DESCIFRADO CON CLAVE SECRETA
 * ------------------------------------------------------------------
 * Se ha utilizado AES/ECB/PKCS5Padding (algoritmo AES, en modo 
 * Electronic Code Book, con relleno PCKS5).
 * El tamaño de la clave generada es 128 bits.
 * Los motivos de esta decisión son:
 * - Mismos motivos que con la generacion de claves secretas
 * 
 * 
 * CIFRADO Y DESCIFRADO CON CLAVE PUBLICA
 * ------------------------------------------------------------------
 * Se ha utilizado RSA/ECB/PCKS5Padding (algoritmo RSA, en modo 
 * Electronic Code Book, con relleno PCKS1). Además, para la 
 * generación de las claves se ha utilizado cierto grado de 
 * aleatoriedad con el algoritmo SHA1PRNG.
 * El tamaño de la clave generada es 1024 bits.
 * Los motivos de esta decisión son:
 * - Mismos motivos que con la generacion de claves publicas
 * 
 * 
 * FIRMA DIGITAL
 * ------------------------------------------------------------------
 * Se ha utilizado RSA/ECB/PCKS5Padding (algoritmo RSA, en modo 
 * Electronic Code Book, con relleno PCKS1) para las claves y SHA-512
 * para el hash.
 * El tamaño de la clave generada es 1024 bits.
 * Los motivos de esta decisión son:
 * - RSA garantiza la confidencialidad de la comunicación.
 * - Para un sistema actual, un par de claves de 1024 bits para 
 * 	 cifrar el hash del mensaje es suficiente ya que romper RSA 
 *   consiste en resolver u problema de factorizacion de primos que 
 *   se alarga segun el tamaño de la clave.
 */

package seguridad.practica5;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PruebasCriptograficas {

	// Variables constantes
	private final static int PUBLIC_KEY_LENGTH = 512;
	private final static int PRIVATE_KEY_LENGTH = 128;
	private final static String ALGORITHM_HASH = "SHA-512";
	private final static String ALGORITHM_PUBLIC = "RSA";
	private final static String ALGORITHM_PUBLIC_STR = "RSA/ECB/PKCS1Padding";
	private final static String ALGORITHM_PRIVATE = "AES";
	private final static String ALGORITHM_PRIVATE_STR = "AES/ECB/PKCS5Padding";
	private final static String ALGORITHM_RANDOM = "SHA1PRNG";

	public static void main(String[] args) throws Exception {
		String usage = "Uso: java PruebasCriptograficas "
				+ "-[hash | generar | almacenar | recuperar | cifrar-descifrar | firma-digital | all]";

		switch (args[0]) {
		case "-hash":
			// Hash con 100 mensajes de tamaño 5000.
			// Opcional: fichero en args[1].
			hash(100, 5000, args[1]);
			break;
		case "-generar":
			// Genera 50 claves publicas y secretas.
			generarClavesPublicas(50, true);
			generarClavesSecretas(50, true);
			break;
		case "-almacenar":
			// Almacena las claves generadas en el fichero args[1].
			almacenarClaves(generarClavesPublicas(50, false), args[1]);
			break;
		case "-recuperar":
			// Recuperar las claves almacenadas en el fichero args[1].
			recuperarClaves(args[1]);
			break;
		case "-cifrar-descifrar":
			// Cifra y descifra 100 mensajes con clave publica y privada
			// Opcional: Ruta del directorio donde hay ficheros
			cifrarDescifrar(100, PUBLIC_KEY_LENGTH * 2, args[1]);
			break;
		case "-firma-digital":
			// Firma digital
			firmaDigital(100);
			break;
		case "-all":
			// Ejecuta todas las opciones
			hash(100, 5000, null);
			System.out.println("----------------------------------------");
			KeyPair[] clavesPublicas = generarClavesPublicas(50, true);
			System.out.println("----------------------------------------");
			generarClavesSecretas(50, true);
			System.out.println("----------------------------------------");
			almacenarClaves(clavesPublicas, "clavesPublicas.txt");
			System.out.println("----------------------------------------");
			recuperarClaves("clavesPublicas.txt");
			System.out.println("----------------------------------------");
			cifrarDescifrar(100, PUBLIC_KEY_LENGTH * 2, null);
			System.out.println("----------------------------------------");
			firmaDigital(100);
			break;
		default:
			System.err.println(usage);
			break;
		}
	}

	/**
	 * Se ha utilizado el algoritmo SHA-512 que puede calcular un hash
	 * para 2^64 - 1 bits y que consiste en 64 rondas de hashing. 
	 * El tamaño de la clave es 512 bits (64 bytes).
	 * @param numMensajes
	 * @param longMensaje
	 * @param fichero
	 */
	public static void hash(int numMensajes, int longMensaje, String fichero) {
		long[] tiempos = new long[numMensajes];
		String mensaje = "";

		if (fichero == null)
			mensaje = generarMensaje(longMensaje);
		else {
			mensaje = leerFichero(fichero);
			longMensaje = mensaje.length();
		}

		for (int i = 0; i < numMensajes; i++) {
			try {
				Date initDate = new Date();
				
				// Crear funcion resumen
				MessageDigest messageDigest = MessageDigest.getInstance(ALGORITHM_HASH);
				byte[] buffer = mensaje.getBytes();
				// Pasa texto claro a la funcion resumen
				messageDigest.update(buffer);
				// Completar el resumen
				buffer = messageDigest.digest();

				Date endDate = new Date();
				tiempos[i] = endDate.getTime() - initDate.getTime();

			} catch (NoSuchAlgorithmException e) {
				System.err.println("Error: " + e.getMessage());
			}
		}

		long mediaTiempo = mediaTiempos(tiempos);
		System.out.println("HASH - Algoritmo: " + ALGORITHM_HASH);
		System.out.printf("Tamaño del mensaje: %d, Numero de mensajes: %d\n", longMensaje, numMensajes);
		System.out.printf("Tiempo ejecucion: %d ms\n", mediaTiempo);
	}

	/**
	 * Se ha utilizado RSA/ECB/PCKS5Padding (algoritmo RSA, en modo 
	 * Electronic Code Book, con relleno PCKS1).
	 * Los tamaños de los pares de claves generadas son 512, 1024 y 2048 bits.
	 * @param numClaves
	 * @param output
	 * @return
	 */
	public static KeyPair[] generarClavesPublicas(int numClaves, boolean output) {
		// Array de pares de claves para los tres tamaños
		KeyPair[] claves = new KeyPair[3];
		for (int i = 0; i < claves.length; i++)
			claves[i] = generarClavePublica(numClaves, i, output);
		return claves;
	}
	
	/**
	 * Se ha utilizado AES.
	 * Los tamaños de las claves generadas son 128, 192 y 256 bits.
	 * @param numClaves
	 * @param output
	 * @return
	 */
	public static SecretKey[] generarClavesSecretas(int numClaves, boolean output) {
		// Array de claves para los tres tamaños
		SecretKey[] claves = new SecretKey[3];
		// Array de los tamaños de las claves
		int[] tamanioClaves = new int[]{128, 192, 256};
		for (int i = 0; i < claves.length; i++)
			claves[i] = generarClaveSecreta(numClaves, tamanioClaves[i], output);
		return claves;
	}

	/**
	 * Almacenamiento del array de pares de claves [parClaves] en el 
	 * fichero [fichero].
	 * @param parClaves
	 * @param fichero
	 */
	public static void almacenarClaves(KeyPair[] parClaves, String fichero) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_PUBLIC);
			for (int i = 0; i < parClaves.length; i++) {
				Date initDate = new Date();

				RSAPublicKeySpec pub = keyFactory.getKeySpec(parClaves[i].getPublic(), RSAPublicKeySpec.class);
				guardarFichero(fichero, pub.getModulus(), pub.getPublicExponent());
				RSAPrivateKeySpec priv = keyFactory.getKeySpec(parClaves[i].getPrivate(), RSAPrivateKeySpec.class);
				guardarFichero(fichero, priv.getPrivateExponent(), priv.getPrivateExponent());

				Date endDate = new Date();
				long tiempo = endDate.getTime() - initDate.getTime();
				
				String[] aux = parClaves[i].getPublic().toString().split("bits")[0].split(" ");
				int pubBits = Integer.valueOf(aux[aux.length-1]);
				aux = parClaves[i].getPrivate().toString().split("bits")[0].split(" ");
				int privBits = Integer.valueOf(aux[aux.length-1]);
				System.out.println("ALMACENAMIENTO DE CLAVES");
				System.out.printf("Tamaño clave publica: %s bits\n", pubBits);
				System.out.printf("Tamaño clave secreta: %s bits\n", privBits);
				System.out.printf("Tiempo de ejecucion: %d ms\n", tiempo);
			}

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
	}

	/**
	 * Recupera el par de claves almacenado en el fichero [fichero]
	 * @param fichero
	 * @return
	 */
	public static KeyPair recuperarClaves(String fichero) {
		System.out.println("RECUPERACION DE CLAVES");
		PublicKey clavePublica = recuperarClavePublica(fichero);
		PrivateKey clavePrivada = recuperarClavePrivada(fichero);
		KeyPair parClave = new KeyPair(clavePublica, clavePrivada);
		return parClave;
	}

	/**
	 * Si la ruta del directorio [path] es null, cifra y descifra
	 * [numItem] mensajes generados aleatoriamente tanto con clave
	 * publica como con secreta.
	 * Si la ruta del directorio [path] no es null, cifra y descifra
	 * el contenido de los ficheros ubicados en el directorio [path]
	 * con clave secreta.
	 * @param numIter
	 * @param tamanioClave
	 * @param path
	 */
	public static void cifrarDescifrar(int numIter, int tamanioClave, String path) {
		List<String> mensajes = new ArrayList<String>();
		int maxTamanioMensaje = maxTamanioClavePublica(tamanioClave, false);

		if (path != null) {
			mensajes = obtenerFicheros(path);
			cifrarDescifrarClaveSecreta(mensajes, PRIVATE_KEY_LENGTH, path);
		} else {
			for (int i = 0; i < numIter; i++) {
				String mensaje = generarMensaje(maxTamanioMensaje);
				mensajes.add(mensaje);
			}
			cifrarDescifrarClavePublica(mensajes, tamanioClave);
			cifrarDescifrarClaveSecreta(mensajes, PRIVATE_KEY_LENGTH, path);
		}
	}

	/**
	 * Cifra y descifra la lista de mensajes [mensajes] con clave publica
	 * con un tamaño de [tamnioClave] bits.
	 * @param mensajes
	 * @param tamanioClave
	 */
	public static void cifrarDescifrarClavePublica(List<String> mensajes, int tamanioClave) {
		long[] cifradoClavePublica = new long[100];
		long[] descifradoClavePublica = new long[100];

		long mediaCifradoClavePublica = 0;
		long mediaDescifradoClavePublica = 0;

		try {
			for (int i = 0; i < mensajes.size(); i++) {
				// Generar clave publica
				KeyPairGenerator generador = KeyPairGenerator.getInstance(ALGORITHM_PUBLIC);
				SecureRandom semilla = SecureRandom.getInstance(ALGORITHM_RANDOM);
				generador.initialize(tamanioClave, semilla);
				KeyPair parClave = generador.generateKeyPair();

				// Cifrado con clave publica
				Date initDate = new Date();
				Cipher cipher = Cipher.getInstance(ALGORITHM_PUBLIC_STR);
				cipher.init(Cipher.ENCRYPT_MODE, parClave.getPrivate());
				byte[] bufferCifrado = cipher.doFinal(mensajes.get(i).getBytes());
				Date endDate = new Date();
				cifradoClavePublica[i] = endDate.getTime() - initDate.getTime();

				// Descifrado con clave publica
				initDate = new Date();
				cipher = Cipher.getInstance(ALGORITHM_PUBLIC_STR);
				cipher.init(Cipher.DECRYPT_MODE, parClave.getPublic());
				cipher.doFinal(bufferCifrado);
				endDate = new Date();
				descifradoClavePublica[i] = endDate.getTime() - initDate.getTime();
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		}

		mediaCifradoClavePublica = mediaTiempos(cifradoClavePublica);
		mediaDescifradoClavePublica = mediaTiempos(descifradoClavePublica);
		System.out.println("CIFRADO CLAVE PUBLICA - Algoritmo: " + ALGORITHM_PUBLIC_STR);
		System.out.printf("Tamaño clave: %d bits, Numero de mensajes: %d\n", tamanioClave, mensajes.size());
		System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaCifradoClavePublica);

		System.out.println("DESCIFRADO CLAVE PUBLICA - Algoritmo: " + ALGORITHM_PUBLIC_STR);
		System.out.printf("Tamaño clave: %d bits, Numero de mensajes: %d\n", tamanioClave, mensajes.size());
		System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaDescifradoClavePublica);
	}

	/**
	 * Cifra y descifra la lista de mensajes [mensajes] con clave secreta
	 * con un tamaño de [tamnioClave] bits.
	 * @param mensajes
	 * @param tamanioClave
	 * @param path 
	 */
	public static void cifrarDescifrarClaveSecreta(List<String> mensajes, int tamanioClave, String path) {
		long[] cifradoClaveSecreta = new long[mensajes.size()];
		long[] descifradoClaveSecreta = new long[mensajes.size()];
		long mediaCifradoClaveSecreta = 0;
		long mediaDescifradoClaveSecreta = 0;

		try {
			for (int i = 0; i < mensajes.size(); i++) {
				// Generar clave secreta
				KeyGenerator generador = KeyGenerator.getInstance(ALGORITHM_PRIVATE);
				generador.init(tamanioClave);
				SecretKey clave = generador.generateKey();

				// Cifrado con clave secreta
				Date initDate = new Date();
				Cipher cifrador = Cipher.getInstance(ALGORITHM_PRIVATE_STR);
				cifrador.init(Cipher.ENCRYPT_MODE, clave);
				byte[] bufferCifrado = cifrador.doFinal(mensajes.get(i).getBytes("UTF-8"));
				Date endDate = new Date();
				cifradoClaveSecreta[i] = endDate.getTime() - initDate.getTime();

				// Descifrado con clave secreta
				initDate = new Date();
				cifrador = Cipher.getInstance(ALGORITHM_PRIVATE_STR);
				cifrador.init(Cipher.DECRYPT_MODE, clave);
				cifrador.doFinal(bufferCifrado);
				endDate = new Date();
				descifradoClaveSecreta[i] = endDate.getTime() - initDate.getTime();
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		}

		mediaCifradoClaveSecreta = mediaTiempos(cifradoClaveSecreta);
		mediaDescifradoClaveSecreta = mediaTiempos(descifradoClaveSecreta);

		System.out.println("CIFRADO CLAVE SECRETA - Algoritmo: " + ALGORITHM_PRIVATE_STR);
		if (path != null) System.out.println("Directorio: " + path);
		System.out.printf("Tamaño clave: %d bits, Numero de mensajes: %d\n", tamanioClave, mensajes.size());
		System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaCifradoClaveSecreta);

		System.out.println("DESCIFRADO CLAVE SECRETA - Algoritmo: " + ALGORITHM_PRIVATE_STR);
		if (path != null) System.out.println("Directorio: " + path);
		System.out.printf("Tamaño clave: %d bits, Numero de mensajes: %d\n", tamanioClave, mensajes.size());
		System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaDescifradoClaveSecreta);
	}

	/**
	 * Firma digital de [numFirmas] mensajes generados de forma aleatoria.
	 * @param numFirmas
	 */
	public static void firmaDigital(int numFirmas) {
		long[] tiempos = new long[numFirmas];
		
		try {
			for (int i = 0; i < numFirmas; i++) {
				byte[] mensaje = generarMensaje(256).getBytes("UTF-8");
				Date initDate = new Date();
				
				int tamanioClave = PUBLIC_KEY_LENGTH * 2;
				KeyPairGenerator generador = KeyPairGenerator.getInstance(ALGORITHM_PUBLIC);
				generador.initialize(tamanioClave);
				KeyPair parClave = generador.generateKeyPair();
				PublicKey clavePublica = parClave.getPublic();
				PrivateKey claveSecreta = parClave.getPrivate();

				// Resumen del mensaje
				MessageDigest resumen = MessageDigest.getInstance(ALGORITHM_HASH);
				resumen.update(mensaje);
				byte[] buffer = resumen.digest(); 

				int maxTamanioClave = maxTamanioClavePublica(tamanioClave, false);
				if (buffer.length > maxTamanioClave) {
					System.out.println("Error, tamaño maximo sobrepasado para el tamaño de clave");
					System.out.printf("Tamaño clave: %d, Tamaño mensaje: %d, Tamaño maximo: %d\n",
							tamanioClave, buffer.length, maxTamanioClave);
				} else {
					// Cifrar el mensaje firmado
					Cipher cipher = Cipher.getInstance(ALGORITHM_PUBLIC_STR);
					// Firma encriptada con la clave publica
					cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
					byte[] bufferEncriptado = cipher.doFinal(buffer);
					// Firma desencriptada con la clave secreta
					cipher.init(Cipher.DECRYPT_MODE, claveSecreta);
					byte[] bufferDesencriptado = cipher.doFinal(bufferEncriptado);
					
					boolean exito = true;
					if (buffer.length != bufferDesencriptado.length) {
						exito = false;
					}
					
					// Comparacion bit a bit
					for (int j = 0; j < buffer.length && exito == true; j++) {
						if (buffer[j] != bufferDesencriptado[j]) {
							exito = false;
						}
					}				
				}
				
				Date endDate = new Date();;
				tiempos[i] = endDate.getTime() - initDate.getTime();
			}
			
			long tiempo = mediaTiempos(tiempos);
			System.out.println("FIRMA DIGITAL");
			System.out.printf("Tiempo de ejecucion medio: %d ms\n", tiempo);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
	}

	/**
	 * Devuelve una cadena aleatoria de caracteres de longitud [numCaracteres].
	 * @param numCaracteres
	 * @return
	 */
	private static String generarMensaje(int numCaracteres) {
		String mensaje = "";
		Random semilla = new Random();
		for (int i = 0; i < numCaracteres; i++) {
			char randomCaracter = (char) semilla.nextInt(128);
			mensaje = mensaje + randomCaracter;
		}
		return mensaje;
	}

	/**
	 * Devuelve un par de claves KeyPair utilizando RSA/ECB/PCKS5Padding 
	 * (algoritmo RSA, en modo Electronic Code Book, con relleno PCKS1).
	 * @param numClaves
	 * @param tamanioClave
	 * @param output
	 * @return
	 */
	private static KeyPair generarClavePublica(int numClaves, int tamanioClave, boolean output) {
		long[] tiempos = new long[numClaves];
		KeyPair parClaves = null;
		// Tamaño de clave := 512*2^tamanioClave, siempre multiplo de 512
		tamanioClave = (int) (PUBLIC_KEY_LENGTH * Math.pow(2, tamanioClave));

		// Se generan numClaves pares de claves por razones de medicion de tiempos y
		// nos quedamos con la ultima generada para devolverla 
		for (int i = 0; i < numClaves; i++) {
			try {
				Date initDate = new Date();

				// Generador de pares de claves
				KeyPairGenerator generador = KeyPairGenerator.getInstance(ALGORITHM_PUBLIC);
				// Aleatoriedad para generar la clave
				SecureRandom semilla = SecureRandom.getInstance(ALGORITHM_RANDOM);
				// Inicializa el generador con el tamaño de clave y la aleatoriedad
				generador.initialize(tamanioClave, semilla);
				// Genera el par de claves
				parClaves = generador.generateKeyPair();

				Date endDate = new Date();
				tiempos[i] = endDate.getTime() - initDate.getTime();
			} catch (NoSuchAlgorithmException e) {
				System.err.println("Error: " + e.getMessage());
			}
		}

		long mediaTiempo = mediaTiempos(tiempos);
		if (output) {
			System.out.println("GENERACION DE CLAVES PUBLICAS - Algoritmo: " + ALGORITHM_PUBLIC);
			System.out.printf("Tamaño de clave: %d bits, Numero de claves: %d\n", tamanioClave, numClaves);
			System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaTiempo);
		}
		return parClaves;
	}
	
	/**
	 * Devuelve una clave secreta SecretKey utilizando AES.
	 * @param numClaves
	 * @param tamanioClave
	 * @param output
	 * @return
	 */
	private static SecretKey generarClaveSecreta(int numClaves, int tamanioClave, boolean output) {
		long[] tiempos = new long[numClaves];
		SecretKey clave = null;

		// Se generan numClaves claves por razones de medicion de tiempos y
		// nos quedamos con la ultima generada para devolverla 
		for (int i = 0; i < numClaves; i++) {
			try {
				Date initDate = new Date();

				// Generador de claves
				KeyGenerator generador = KeyGenerator.getInstance(ALGORITHM_PRIVATE);
				// Inicializa el generador con el tamaño de clave
				generador.init(tamanioClave);
				// Genera la clave secreta
				clave = generador.generateKey();

				Date endDate = new Date();
				tiempos[i] = endDate.getTime() - initDate.getTime();
			} catch (NoSuchAlgorithmException e) {
				System.err.println("Error: " + e.getMessage());
			}
		}

		long mediaTiempo = mediaTiempos(tiempos);
		if (output) {
			System.out.println("GENERACION DE CLAVES SECRETAS - Algoritmo: " + ALGORITHM_PRIVATE);
			System.out.printf("Tamaño de clave: %d bits, Numero de claves: %d\n", tamanioClave, numClaves);
			System.out.printf("Tiempo de ejecucion medio: %d ms\n", mediaTiempo);
		}
		return clave;
	}

	/**
	 * Recupera la clave publica almacenada en el fichero [fichero]
	 * @param fichero
	 * @return
	 */
	private static PublicKey recuperarClavePublica(String fichero) {
		InputStream in;
		ObjectInputStream oin;
		PublicKey clavePublica = null;
		long tiempo = 0;
		try {
			in = new FileInputStream(fichero);
			oin = new ObjectInputStream(new BufferedInputStream(in));

			Date initDate = new Date();

			// Clave publica
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			RSAPublicKeySpec publickeySpec = new RSAPublicKeySpec(m, e);
			KeyFactory keyfactory = KeyFactory.getInstance(ALGORITHM_PUBLIC);
			clavePublica = keyfactory.generatePublic(publickeySpec);
			
			Date endDate = new Date();
			tiempo = endDate.getTime() - initDate.getTime();

			oin.close();
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		} finally {
			System.out.printf("Clave publica - Tiempo de ejecucion: %d ms\n", tiempo);
		}
		return clavePublica;
	}

	/**
	 * Recupera la clave secreta almacenada en el fichero [fichero]
	 * @param fichero
	 * @return
	 */
	private static PrivateKey recuperarClavePrivada(String fichero) {
		InputStream in;
		ObjectInputStream oin;
		PrivateKey clavePrivada = null;
		long tiempo = 0;
		try {
			in = new FileInputStream(fichero);
			oin = new ObjectInputStream(new BufferedInputStream(in));

			Date initDate = new Date();
			
			// Clave secreta
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			RSAPrivateKeySpec privatekeySpec = new RSAPrivateKeySpec(m, e);
			KeyFactory keyfactory = KeyFactory.getInstance(ALGORITHM_PUBLIC);
			clavePrivada = keyfactory.generatePrivate(privatekeySpec);
			
			Date endDate = new Date();
			tiempo = endDate.getTime() - initDate.getTime();

			oin.close();
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
		} finally {
			System.out.printf("Clave privada - Tiempo de ejecucion: %d ms\n", tiempo);
		}
		return clavePrivada;
	}

	/**
	 * Devuelve el maximo tamaño de mensaje que se puede cifrar con
	 * criptografica de clave publica.
	 * @param tamanioClave
	 * @return
	 */
	private static int maxTamanioClavePublica(int tamanioClave, boolean output) {
		if (tamanioClave < PUBLIC_KEY_LENGTH)
			return 0;
		int maximoTamanio = 0;

		try {
			KeyPairGenerator generador = KeyPairGenerator.getInstance(ALGORITHM_PUBLIC);
			SecureRandom semilla = SecureRandom.getInstance(ALGORITHM_RANDOM);
			generador.initialize(tamanioClave, semilla);
			KeyPair parClave = generador.generateKeyPair();
			while (true) {
				String mensaje = generarMensaje(maximoTamanio);
				Cipher cipher = Cipher.getInstance(ALGORITHM_PUBLIC_STR);
				cipher.init(Cipher.ENCRYPT_MODE, parClave.getPrivate());
				cipher.doFinal(mensaje.getBytes());
				maximoTamanio++;
			}
		} catch (Exception e) {
			if (output)
				System.out.printf("Maximo tamaño mensaje a cifrar: %d bytes\n", (maximoTamanio - 1));
		}
		return maximoTamanio - 1;
	}

	/**
	 * Devuelve una cadena de texto con el contenido del fichero [fichero].
	 * @param fichero
	 * @return
	 */
	private static String leerFichero(String fichero) {
		Path path = Paths.get(fichero);
		byte[] datos;
		String contenido = null;
		try {
			datos = Files.readAllBytes(path);
			contenido = new String(datos, "UTF-8");
		} catch (IOException e) {
			System.err.println("Error: " + e.getMessage());
		}
		return contenido;
	}

	/**
	 * Guarda en el fichero [fichero] la clave publica con modulo [mod]
	 * y exponente [exp];
	 * @param fichero
	 * @param mod
	 * @param exp
	 */
	private static void guardarFichero(String fichero, BigInteger mod, BigInteger exp) {
		ObjectOutputStream oout = null;
		try {
			oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fichero)));
			oout.writeObject(mod);
			oout.writeObject(exp);
			oout.close();
		} catch (IOException e) {
			System.err.println("Error: " + e.getMessage());
		}
	}

	/**
	 * Devuelve una lista con el contenido de los ficheros que se encuentran en
	 * el directorio [path].
	 * @param path
	 * @return
	 */
	private static List<String> obtenerFicheros(String path) {
		List<String> resultado = new ArrayList<String>();
		File[] ficheros = new File(path).listFiles();
		for (File fichero : ficheros) {
			if (fichero.isFile()) {
				String contenido = leerFichero(fichero.toString());
				resultado.add(contenido);
			}
		}
		return resultado;
	}

	/**
	 * Devuelve el array de bytes [resumen] codificado en 
	 * hexadecimal.
	 * @param resumen
	 * @return
	 */
	@SuppressWarnings("unused")
	private static String mensajeCodificado(byte[] resumen) {
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < resumen.length; i++) {
			hexString.append(Integer.toHexString(0xFF & resumen[i]));
		}
		return hexString.toString();
	}

	/**
	 * Devuelve un long con el valor medio del array [tiempos].
	 * @param tiempos
	 * @return
	 */
	private static long mediaTiempos(long[] tiempos) {
		long tiempo = 0;
		for (int i = 0; i < tiempos.length; i++) {
			tiempo += tiempos[i];
		}
		tiempo = (long) (tiempo / tiempos.length);
		return tiempo;
	}
}