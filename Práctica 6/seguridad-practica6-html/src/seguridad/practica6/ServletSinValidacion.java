package seguridad.practica6;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 
 * @author Rafael Marcén Altarriba (650435)
 * @version 1.0
 *
 */
public class ServletSinValidacion extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) {
		String nombre = request.getParameter("nombre");
		String direccion = request.getParameter("direccion");
		String tipo = request.getParameter("tipo");
		String numero = request.getParameter("numero");
		String mesexpira = request.getParameter("mesexpira");
		String anioexpira = request.getParameter("anioexpira");
		String cvn = request.getParameter("cvn");
		String dni = request.getParameter("dni");

		request.setAttribute("nombre", nombre);
		request.setAttribute("direccion", direccion);
		request.setAttribute("tipo", tipo);
		request.setAttribute("numero", numero);
		request.setAttribute("mesexpira", mesexpira);
		request.setAttribute("anioexpira", anioexpira);
		request.setAttribute("cvn", cvn);
		request.setAttribute("dni", dni);		
		
		RequestDispatcher view = request.getRequestDispatcher("/Resultado.jsp");
		try {
			view.forward(request, response);
		} catch (ServletException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}