from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import number
import random
##
#@file
#

## @package Encriptacion
# Modulo que proporciona metodos para cifrar y descifrar un archivo haciendo 
# uso de AES
#

##
# Texto extra para generar palabras al azar en caso de que el archivo con las llaves
# sea incorrecto
#
trash = "The Witcher: Wild Hunt is a story-driven, next-generation open world"
trash = trash + "role-playing game set in a visually stunning fantasy universe "
trash = trash + "full of meaningful choices and impactful consequences. In The"
trash = trash +  "Witcher you play as the professional monster hunter, Geralt of "
trash = trash + "Rivia, tasked with finding a child of prophecy in a vast open"
trash = trash + " world rich with merchant cities, viking pirate islands, dange"
trash = trash + "rous mountain passes, and forgotten caverns to explore. "

##
# 
# Aplica el hash SHA-256 a una contrasena (string)
# @clave la clave a la cual se aplicar el hash
# @return Un string con la representacion en bits de la clave despues de haber 
# aplicado el hash
#
def aplicaSha(clave):
	convertidor = SHA256.new()
	convertidor.update(clave)
	return convertidor.digest()


##
# 
# Complementa un bloque de datos con el caracter nul para formar un bloque cuyo
# numero de bytes sea un multiplo de 16
# @param datos Los datos a completar en bytes para que sean un multiplo de 16
# @return Una tupla donde la primer entrada son los datos completados y en la 
# segunda entrada una cadena que representa el numero de caracteres nul agregados
#
def complementaDatos(datos):
	datosARellenar = 16 - (len(datos) % 16)
	for n in range(datosARellenar):
		datos = datos + ' '
	if datosARellenar < 10:
		datosRelleno = "0" + str(datosARellenar)
	else:
		datosRelleno = str(datosARellenar)
	return datos, datosRelleno

##
# Encripta un bloque de datos utilizando AES, a partir de un clave proporcionada,
# tambien se anexa el nombre del archivo al bloque de datos encriptados
# @param llave La clave para encriptar los datos
# @param texto El bloque de datos a encriptar
# @param nombreArchivo El nombre del archivo donde pertenecen el bloque de datos
# @return Una cadena con la representacion en bytes del archivo encriptado
#
def encriptaAES(llave, texto, nombreArchivo):
	cifrador = AES.new(llave, AES.MODE_ECB, "nom importa")
	info = complementaDatos(texto)
	texto = cifrador.encrypt(info[0])
	texto = info[1] + "\0" + texto
	texto = "\0" + nombreArchivo + texto
	texto = str(len(nombreArchivo)) + texto
	return texto

##
# Elimina los caracteres nul agregado a un bloque de datos por el metodo comple-
# menta datos
# @param texto El bloque de datos a depurar
# @param datosAEliminar la cantidad de caracteres nul que se quiere eliminar
# @return El bloque de datos con los caracteres nul removidos
def eliminaDatosBasura(texto, datosAEliminar):
	salida = texto[0:len(texto) - datosAEliminar - 16]
	return salida


##
# Descifra un bloque de datos encriptado por AES dado la llave con la que fue cifrado
# Si la llave que se proporciona no es la correcta, el bloque de datos descifrado
# probablemente no tenga sentido
# @param llave La clave con la que se cifraron los datos
# @param texto El bloque de datos cifrado por AES
# @return El bloque de datos descifrado
#
def descifraAES(llave, texto):
	try:
		descifrador = AES.new(llave, AES.MODE_ECB, "no importa")
		informacion = texto.split("\0", 1)
		longitudTitulo = int(informacion[0])
		titulo = informacion[1][0:longitudTitulo]
		texto = informacion[1][longitudTitulo:]
		informacion = texto.split("\0", 1)
		datosAEliminar = int(informacion[0])
		texto =  descifrador.decrypt(informacion[1])
		datos = eliminaDatosBasura(texto, datosAEliminar)
		return titulo, datos
	except ValueError:
		titulo = str(''.join(random.choice(trash) for _ in range(5)))
		texto = str(''.join(random.choice(trash) for _ in range(500)))
		return titulo, texto
	

