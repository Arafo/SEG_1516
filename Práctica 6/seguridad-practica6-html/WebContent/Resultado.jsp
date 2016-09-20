<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Resultado</title>
</head>
<body>
	<c:choose>
		<c:when test="${! error}">
			<h2>Resultado</h2>
			<label for="IdNombre">Nombre: </label>${nombre}<br/>
			<label for="IdDireccion">Direccion: </label>${direccion}<br/>
			<fieldset style="border: 0px; padding: 0em;">
				<legend style="padding: 0px; border-radius: 0px; margin-left: 0px">Tarjeta de credito</legend>
				<label for="IdTipo">Tipo: </label>${tipo}<br/> <label for="IdNumero">Numero:</label>${numero}<br/>
				<label for="IdMesExpira">Mes Expira: </label>${mesexpira}<br/> 
				<label for="IdAnioExpira">Año Expira: </label>${anioexpira}<br/> 
				<label for="IdCVN">CVN: </label>${cvn}<br/>
			</fieldset>
			<label for="IdDNI">DNI: </label>${dni}<br/>
		</c:when>
		<c:otherwise>
			<h2>Error de validacion</h2>
			<p>${mensajeerror}</p>
		</c:otherwise>
	</c:choose>
	<input id="IdVolver" type="button" onclick="volver()" value="Volver"/>
	<script>
		function volver() {
			window.history.back();	
		}
	</script>
</body>
</html>