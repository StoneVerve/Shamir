import sys
import getpass
from Encriptacion import *
from Shamir import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import number
##
#@file
#

##
# @package Main
# Encripta un archivo y fragmenta la clave en n llaves
#

primo = 208351617316091241234326746312124448251235562226470491514186331217050270460481

##
# Valida que el numero de llaves se indicado
# @param llaves El maximo numero de llaves
# @param minLlaves El minimo numero de llaves para recuperar la clave
# @return true si el numero de llaves es correcto y false en otro caso
def validaNumeroLlaves(llaves, minLlaves):
	if llaves <= 0 or minLlaves <= 0 or minLlaves > llaves:
		return llaves is not llaves
	else:
		return llaves is llaves

##
# Lee un archivo
# @param archivo el nombre del archivo a leer
# @return el contenido del archivo
def leerArchivo(archivo):
	lector = open(archivo, 'r')
	texto = lector.read()
	lector.close()
	return texto 

## 
# Escribe un archivo
# @param nombre El nombre del archivo a escribir
# @param contenido El contenido a escribir en el archivo
def escribeArchivo(nombre, contenido):
	escritor = open(nombre, 'w')
	escritor.write(contenido)
	escritor.close()

##
# Pasa el conjunto de llaves generado por Shamir a un string para ser escrito en
# un archivo
# @param llaves La lista con las llaves que se va a formatear
# @return Una cadena con las llaves organizadas
def aTextoLlaves(llaves):
	llavesSalida = ""
	for i in llaves:
		punto = str(i)
		punto = punto.replace("[", "(")
		punto = punto.replace("]", ")")
		llavesSalida = llavesSalida + punto + "\n"
	return llavesSalida

##
# Pasa un conjunto de llaves en string generado por aTextoLlaves a una lista de 
# llaves
# @param llaves La cadena con las llaves
# @return Una lista con las llaves(Cada una es una tupla)
def aLongLlaves(llaves):
	llavesTexto = llaves.split("\n")
	llavesNum = list()
	for punto in llavesTexto:
		actual = punto.split(",")
		if (len(actual) == 2):
			x = actual[0]
			y = actual[1]
			llavesNum.append([long(x[1:]), long(y[:len(y) - 1])])
	return llavesNum

## 
# Programa principal
#
parametros = sys.argv
entradaStd = sys.stdin

if  len(parametros) == 6 and parametros[1] == "c":
	try:
		nombreArchivoLlaves = parametros[2]
		numeroDeLlaves = int(parametros[3])
		numeroMinLlaves = int(parametros[4])
		nombreArchivo = parametros[5]
		if validaNumeroLlaves(numeroDeLlaves, numeroMinLlaves):
			clave = getpass.getpass("Clave:")
			clave = aplicaSha(clave)
			texto = leerArchivo(nombreArchivo)
			terminoInd = number.bytes_to_long(clave)
			llaves = generaLlaves(terminoInd, numeroDeLlaves, numeroMinLlaves)
			texto = encriptaAES(clave, texto, nombreArchivo)
			escribeArchivo(nombreArchivoLlaves + ".aes", texto)
			escribeArchivo(nombreArchivoLlaves + ".frg", aTextoLlaves(llaves))
		else:
			salida = "El numero de llaves debe ser mayor que cero y el numero minimo de "
			print salida + "debe der menor que el numero total de llaves"
	except IOError:
		salida =  "No se puedo abrir el archivo con los datos o no se econtro el"
		salida = salida + " el archivo indicado o no se tiene permiso para"
		print salida + " escribir en el directorio"
	except ValueError:
		print "No se ingreso un numero valido para las llaves"
	
elif len(parametros) == 4 and parametros[1] == "d":
	try:
		archivoCifrado = parametros[3]
		archivoLlaves = parametros[2]
		llavesTexto = leerArchivo(archivoLlaves)
		llaves = aLongLlaves(llavesTexto)
		clave = recuperaClave(llaves)
		clave = number.long_to_bytes(clave)
		textoCodificado = leerArchivo(archivoCifrado)
		archivoLimpio = descifraAES(clave, textoCodificado)
		escribeArchivo(archivoLimpio[0], archivoLimpio[1])
	except IOError:
		salida =  "No se puedo abrir el archivo con los datos o no se econtro el"
		salida = salida + " el archivo indicado o no se tiene permiso para"
		print salida + " escribir en el directorio"
	except ValueError:
		salida = "Verifica que el archivo de las llaves cada una sea de la forma "
		print salida + "(numero, numero) y que cada llave este separada por un salto de linea"
else:
	print "Opcion no Valida"

