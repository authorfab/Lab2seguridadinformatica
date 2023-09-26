import hashlib

# Laboratorio 2 Seguridad Informatica
# Fabian Urra - Jose Castillo 

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------

def calcular_hash(texto):
    sha256 = hashlib.sha256()
    sha256.update(texto.encode('utf-8'))
    hash_resultado = sha256.hexdigest()
    return hash_resultado


def cifrado_cesar(texto, n):
    resultado = ""
    for letra in texto:
        if letra.isalpha():
            offset = ord('a') if letra.islower() else ord('A')
            resultado += chr((ord(letra) - offset + n) % 26 + offset)
        else:
            resultado += letra
    return resultado

def descifrado_cesar(texto, n):
    return cifrado_cesar(texto, -n)

def cifrado_vigenere(texto, clave):
    resultado = ""
    clave_index = 0
    for letra in texto:
        if letra.isalpha():
            offset = ord('a') if letra.islower() else ord('A')
            clave_letra = clave[clave_index % len(clave)]
            clave_offset = ord('a') if clave_letra.islower() else ord('A')
            resultado += chr((ord(letra) - offset + ord(clave_letra) - clave_offset) % 26 + offset)
            clave_index += 1
        else:
            resultado += letra
    return resultado

def descifrado_vigenere(texto, clave):
    resultado = ""
    clave_index = 0
    for letra in texto:
        if letra.isalpha():
            offset = ord('a') if letra.islower() else ord('A')
            clave_letra = clave[clave_index % len(clave)]
            clave_offset = ord('a') if clave_letra.islower() else ord('A')
            resultado += chr((ord(letra) - offset - (ord(clave_letra) - clave_offset)) % 26 + offset)
            clave_index += 1
        else:
            resultado += letra
    return resultado

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------

with open('mensajedeentrada.txt', 'r') as archivo_entrada:
    mensaje_original = archivo_entrada.read()

print("Este es el mensaje original:", mensaje_original)

m_hash1 = calcular_hash(mensaje_original)
print("Se ha realiazdo el hash al mensaje")

n = 15  
clave_vigenere = "CLAVE"

mensaje_cifrado_rot_n = cifrado_cesar(mensaje_original, n)
mensaje_cifrado_vigenere = cifrado_vigenere(mensaje_cifrado_rot_n, clave_vigenere)

with open('mensajeseguro.txt', 'w') as archivo_seguro:
    archivo_seguro.write(mensaje_cifrado_vigenere)

print("El mensaje cifrado se ha guardado en 'mensajeseguro.txt'")

with open('mensajeseguro.txt', 'r') as archivo_seguro2:
    mensaje_cifrado = archivo_seguro2.read()

descifra = descifrado_vigenere(mensaje_cifrado,clave_vigenere)
descifra2 = descifrado_cesar(descifra,n)

print("El mensaje decifrado es:", descifra2)

m_hash2 = calcular_hash(descifra2)

if m_hash1 == m_hash2:
    print("El mensaje no ha sido moficado")