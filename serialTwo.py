import serial
import time

ser = serial.Serial("COM9", 115200, timeout=1)

# 1. Ler entrada.txt
with open("entrada.txt", "r") as f:
    texto = f.read()

# 2. Converter para ASCII e enviar
vetor = [ord(c) for c in texto]

tamanho = 2048
resposta = ""

shake = ""
handshake = "limpa"
ser.write(bytes(handshake, 'ascii'))
while shake != handshake:
    time.sleep(0.01)
    shake = ser.read(5+3)
    shake = str(shake)
    shake = shake.replace("b",'')
    shake = shake.replace("'",'')
    print(shake)

for i in range(0,len(vetor),tamanho):
    blocoAtual = vetor[i:i+tamanho]
    
    
    ser.write(bytes(blocoAtual))

    time.sleep(0.01)
    # 3. Ler resposta (até 16 bytes)
    resp = ser.read(tamanho*7 + 3)
    
    resp = str(resp)
    resp = resp.replace("b",'')
    resp = resp.replace("'",'')

    resposta += resp

print(resposta)


# salva no arquivo
with open("cifra.txt", "w") as f:
    f.write(str(resposta))

print("Arquivo cifra.txt gerado com sucesso!")

ser.close()
