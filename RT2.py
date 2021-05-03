from cryptography.fernet import Fernet 					#simetrica
import subprocess
import rsa 									#assimetrica
import json


def main():

	BOB_pkarq = open('Chaves/pubkeyBOB.pem', 'rb')
	BOB_pk = rsa.PublicKey.load_pkcs1_openssl_pem(BOB_pkarq.read())	#pegando pk de BOB
	BOB_pkarq.close()
	
	pacoteBOB = cebola(BOB_pk, 'teste321!')				#criando pacote de BOB
		
	S3_pkarq = open('Chaves/pubkeyS3.pem', 'rb')
	S3_pk = rsa.PublicKey.load_pkcs1_openssl_pem(S3_pkarq.read())	#pegando pk do "Servidor 3"
	S3_pkarq.close()
	    	
	pacoteS3 = cebola(S3_pk, str(pacoteBOB))				#criando pacote do "Servidor 3"
    	
	S2_pkarq = open('Chaves/pubkeyS2.pem', 'rb')
	S2_pk = rsa.PublicKey.load_pkcs1_openssl_pem(S2_pkarq.read())	#pegando pk do "Servidor 2"
	S2_pkarq.close()
	
	pacoteS2 = cebola(S2_pk, str(pacoteS3))				#criando pacote do "Servidor 2"
	
	S1_pkarq = open('Chaves/pubkeyS1.pem', 'rb')
	S1_pk = rsa.PublicKey.load_pkcs1_openssl_pem(S1_pkarq.read())	#pegando pk do "Servidor 1"
	S1_pkarq.close()
	
	pacoteS1 = cebola(S1_pk, str(pacoteS2))				#criando pacote do "Servidor 1"
	
	
	mensagem = servidor1(pacoteS1)					#enviando o pacote para o "Servidor 1"
	
	print(mensagem)
	

def cebola(pk,mensagem):							#funcao para criar as camadas	
	
	chave = Fernet.generate_key()
	ch = Fernet(chave)
	chaveencrypt = rsa.encrypt(chave, pk).hex()
	mensagemencrypt = ch.encrypt(mensagem.encode('utf8')).decode('utf8')
	pacote = [chaveencrypt,mensagemencrypt]
	pacotej = json.dumps(pacote)						#json usado para ser possivel encriptar a lista
	return pacotej
	
	
def descascar(chave,mensagem):						#funcao para tirar as camadas
	
	novaMsg = chave.decrypt(bytes(mensagem, 'utf8')).decode()
	return novaMsg


def getSK(caminho):								#funcao para pegar a SK
	SKarq = open(caminho, 'rb')
	SKlida = SKarq.read()
	SK = rsa.PrivateKey._load_pkcs1_pem(SKlida)
	SKarq.close()
	return SK
	
	
def bob(pacotej):
	SK = getSK('Chaves/privkeyBOB.pem')
	pacote = json.loads(pacotej)						#voltando para lista
	chavedecrypt = rsa.decrypt(bytes.fromhex(pacote[0]), SK)
	chave = Fernet(chavedecrypt)
	mensagem = descascar(chave,pacote[1])
	return mensagem


def servidor1(pacotej):
	SK = getSK('Chaves/privkeyS1.pem')
	pacote = json.loads(pacotej)						#voltando para lista
	chavedecrypt = rsa.decrypt(bytes.fromhex(pacote[0]), SK)
	chave = Fernet(chavedecrypt)
	novoPacote = descascar(chave,pacote[1])
	mensagem = servidor2(novoPacote)
	return mensagem



def servidor2(pacotej):
	SK = getSK('Chaves/privkeyS2.pem')
	pacote = json.loads(pacotej)						#voltando para lista
	chavedecrypt = rsa.decrypt(bytes.fromhex(pacote[0]), SK)
	chave = Fernet(chavedecrypt)
	novoPacote = descascar(chave,pacote[1])
	mensagem = servidor3(novoPacote)
	return mensagem



def servidor3(pacotej):
	SK = getSK('Chaves/privkeyS3.pem')
	pacote = json.loads(pacotej)						#voltando para lista 
	chavedecrypt = rsa.decrypt(bytes.fromhex(pacote[0]), SK)
	chave = Fernet(chavedecrypt)
	novoPacote = descascar(chave,pacote[1])
	mensagem = bob(novoPacote)
	return mensagem
	
	

if __name__ == "__main__":
    main()
