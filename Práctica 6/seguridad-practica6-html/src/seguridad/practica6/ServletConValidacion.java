package seguridad.practica6;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * 
 * @author Rafael Marcén Altarriba (650435)
 * @version 1.0
 *
 */
public class ServletConValidacion extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) {
		boolean error = false;
		String mensajeerror = null;

		String nombre = request.getParameter("nombre");
		String direccion = request.getParameter("direccion");
		String tipo = request.getParameter("tipo");
		String numero = request.getParameter("numero");
		String mesexpira = request.getParameter("mesexpira");
		String anioexpira = request.getParameter("anioexpira");
		String cvn = request.getParameter("cvn");
		String dni = request.getParameter("dni");
		
		// Validacion
		Validator validator = ESAPI.validator();
		try {
			// Nombre
			validator.getValidInput("Nombre", nombre, "Nombre", 50, false);
			// Direccion					
			validator.getValidInput("Direccion", direccion, "Direccion", 50, false);
			// Tipo (Tarjeta de credito)
			validator.getValidInput("Tipo", tipo, "Tipo", 4, false);
			// Numero (Tarjeta de credito)
			validator.getValidCreditCard("Numero", numero, false);
			// Mes Expira (Tarjeta de credito)
			validator.getValidInput("Mes Expira", mesexpira, "MesExpira", 2, false);
			// Año expira (Tarjeta de credito)
			validator.getValidInput("Año Expira", anioexpira, "AnioExpira", 4, false);
			// CVN (Tarjeta de credito)
			validator.getValidInput("CVN", cvn, "CVN", 3, false);
			// DNI
			validator.getValidInput("DNI", dni, "DNI", 9, false);
		} catch (ValidationException e) {
			error = true;
			mensajeerror = e.getMessage();
		} catch (IntrusionException e) {
			error = true;
			mensajeerror = e.getMessage();
		}
		
		request.setAttribute("nombre", nombre);
		request.setAttribute("direccion", direccion);
		request.setAttribute("tipo", tipo);
		request.setAttribute("numero", numero);
		request.setAttribute("mesexpira", mesexpira);
		request.setAttribute("anioexpira", anioexpira);
		request.setAttribute("cvn", cvn);
		request.setAttribute("dni", dni);
		request.setAttribute("error", error);
		request.setAttribute("mensajeerror", mensajeerror);

		RequestDispatcher view = request.getRequestDispatcher("/Resultado.jsp");
		try {
			view.forward(request, response);
		} catch (ServletException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}
}