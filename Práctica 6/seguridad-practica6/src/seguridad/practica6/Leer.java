package seguridad.practica6;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.MySQLCodec.Mode;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * 
 * @author Rafael Marcén Altarriba (650435)
 * @version 1.0
 *
 */
public class Leer {

	public static void main (String[] args) {
		String uso = "Uso: java Leer [-v] [-c] [-e (SQL | HTML | URL)]";
		boolean validar = false;
		boolean canonicalizar = false;
		boolean codificar = false;
		List<String> codificaciones = new ArrayList<String>();
		List<String> entradas = new ArrayList<String>();
		
		if (args.length == 0) {
			System.err.println(uso);
			System.exit(0);
		}
		
		// Obtener los argumentos
		for (int i=0; i<args.length; i++) {
			if (args[i].equals("-v"))
				validar = true;
			else if (args[i].equals("-c"))
				canonicalizar = true;
			else if (args[i].equals("-e")) {
				codificar = true;
				String codificacion = i+1 < args.length ? args[i + 1].toUpperCase() : "";
				if (codificacion.equals("SQL") || codificacion.equals("HTML") || codificacion.equals("URL"))
					codificaciones.add(codificacion);
				else {
					System.err.println(uso);
					System.exit(0);
				}
				i = i + 1;
			}
			else {
				System.err.println(uso);
				System.exit(0);
			}
		}
		
		// Leer fichero linea por linea de la entrada estandar
	    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        String line = null;  
        try {
			while (entradas.size() < 8 && (line = input.readLine()) != null) { 
				entradas.add(line);
				//System.out.println(line);
			}
	        input.close();
		} catch (IOException e) {
			System.err.println("Error al leer el fichero");
			System.exit(0);
		}
		
		Encoder encoder = ESAPI.encoder();
		Validator validator = ESAPI.validator();
				
		// Canonicalizar
		if (canonicalizar) {
			canonicalizar(encoder, entradas);
		}
		
		// Validar
		if (validar) {
			validar(validator, entradas);
		}
		
		// Codificar
		if (codificar) {
			codificar(encoder, entradas, codificaciones);
		}
	}
	
	private static void canonicalizar(Encoder encoder, List<String> entradas) {
		System.out.println("----------------------------------------");
		System.out.println("CANONICALIZAR");
		System.out.println("----------------------------------------");
		for (int i=0; i<entradas.size(); i++) {
			entradas.set(i, encoder.canonicalize(entradas.get(i)));
			System.out.println(entradas.get(i));
		}
	}
	
	private static void validar(Validator validator, List<String> entradas) {
		//System.out.println("----------------------------------------");
		for (int i=0; i<entradas.size(); i++) {
			String entrada = null;
			try {
				switch (i) {
				// Nombre
				case 0 :
					entrada = validator.getValidInput("Nombre", entradas.get(i), "Nombre", 50, false);
					break;
				// Direccion					
				case 1 :
					entrada = validator.getValidInput("Direccion", entradas.get(i), "Direccion", 50, false);
					break;
				// Tipo (Tarjeta de credito)
				case 2 :
					entrada = validator.getValidInput("Tipo", entradas.get(i), "Tipo", 50, false);
					break;
				// Numero
				case 3 :
					entrada = validator.getValidCreditCard("Numero", entradas.get(i), false);
					//entrada = validator.getValidInput("Numero", entradas.get(i), "Numero", 12, false);
					break;
				// Mes Expira
				case 4 :
					entrada = validator.getValidInput("Mes Expira", entradas.get(i), "MesExpira", 50, false);
					break;
				// Año expira
				case 5 :
					entrada = validator.getValidInput("Año Expira", entradas.get(i), "AnioExpira", 50, false);
					break;
				// CVN (Tarjeta de credito)
				case 6 :
					entrada = validator.getValidInput("CVN", entradas.get(i), "CVN", 50, false);
					break;
				// DNI
				case 7 :
					entrada = validator.getValidInput("DNI", entradas.get(i), "DNI", 50, false);
					break;
				}

				//System.out.println(entrada);
			} catch (ValidationException e) {
				System.err.println("Error en la validacion de la entrada: " + entradas.get(i));
				System.exit(0);
			} catch (IntrusionException e) {
				e.printStackTrace();
			}
		}
	}
	
	private static void codificar(Encoder encoder, List<String> entradas, List<String> codificaciones) {
		// Para todas las codificaciones especificadas en la entrada
		for (String codificacion : codificaciones) {
			System.out.println("----------------------------------------");
			System.out.println("CODIFICACION - "+ codificacion);
			System.out.println("----------------------------------------");
			Codec codec = null;
			if (codificacion.equals("SQL"))
				codec = new MySQLCodec(Mode.STANDARD);
			if (codificacion.equals("HTML"))
				codec = new HTMLEntityCodec();
			if (codificacion.equals("URL"))
				codec = new PercentCodec();
			for (String entrada : entradas) {
				System.out.println(encoder.encodeForSQL(codec, entrada));
			}
		}
	}
}