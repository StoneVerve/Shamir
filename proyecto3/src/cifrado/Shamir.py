from random import randint
from Crypto.Util import number
##
#@file
#

## @package Shamir
# Modulo que proporciona metodos para a partir de una clave fragmentarla
# en multiples partes utilizando el esquema de Shamir
# Todos los coeficientes pertenecen al campo Zp donde p es el primo indicado en 
# la parte inferior
#

primo = 208351617316091241234326746312124448251235562226470491514186331217050270460481

## 
# @brief Genera un polinomio del grado indicado cuyo termino independiente es dado
# todos lo coeficientes pertenecen a Zp
# Genera un polinomio del grado indicado cuyo termino independiente es dado
# todos lo coeficientes pertenecen a Zp
# @param grado El grado del polinomio
# @param terminoInd El termino independiente del polinomio
# @return Una lista con los coeficientes del polinomio desde el coeficiente de entrada
# hasta el termino independiente
def creaPolinomio(grado, terminoInd):
	polinomio = list()
	for i in range(grado):
		polinomio.append(randint(0, primo))
	polinomio.append(terminoInd)
	return polinomio

##
# @brief Evalua un Polinomio utilizando la regla de Horner
# @param polinomio El polinomio (lista con coeficientes del polinomio) donde se
# evaluaran los puntos
# @param x la coordenada x donde se evaluara el polinomio
# @return La coordenada y correspondiente al evaluar x en el polinomio
def evaluaPolinomio(polinomio, x):
	y = 0
	for i in polinomio:
		y = (((y * x) % primo) + i) % primo
	return y

##
# @brief Fragmente un contrasena en un numero determinado de llaves(puntos) a partir de 
# los cuales se puede reconstruir la contrasena
# @param clave La clave que se desea fragmentar
# @param numLlaves el numero de fragmentos que se quiere generar
# @param minLlaves el minimo numero de fragmentos necesarios para reconstruir 
# la contrasena
# @return Una lista cuyos elemenros son listas (tuplas) de enteros que repre-
# sentan los distintos fragmentos
def generaLlaves(clave, numLlaves, minLlaves):
	polinomio = creaPolinomio(minLlaves - 1, clave)
	llaves = list()
	for i in range(numLlaves):
		x = randint(1, primo)
		y = evaluaPolinomio(polinomio, x)
		llaves.append([x, y])
	return llaves

##
# @brief Recupera una contrasena a partir de un conjuntos de fragmentos correspondientes
# a la contrasena
# @param llaves Una listas cuyos elementos son listas(tuplas) de enteros que 
# representan los fragmentos de la clave cuya longitud es al menos el minimo numero
# de fragmentos necesarios para recuperar la contrasena.
# @return Un entero que representa la contrasena cuyos fragmentos son los descritos
# en la lista proporcionada
def recuperaClave(llaves):
	clave = 0
	for punto in llaves:
		x = punto[0]
		y = punto[1]
		clave = (clave + (y * calculaPolinomioBase(x, llaves)) % primo) % primo
	return clave

##
# @brief Metodo auxiliar para "recuperaClave" que calcula un polinomioBase perteneciente
# al metodo de interpolacion de polinomios de Lagrange
# @param x La coordenada x del punto
# @param llaves La lista con los multiples puntos del polinomio
# @return El polinomioBase x
def calculaPolinomioBase(x, llaves):
	numerador = 1
	denominador = 1
	x1 = 0
	for punto in llaves:
		x1 = punto[0] 
		if (x1 != x):
			numerador = ((numerador) * ((-1) * x1)) % primo
			denominador = (denominador * ((x - x1) % primo)) % primo
	denominador = number.inverse(denominador, primo)
	return (numerador * denominador) % primo
