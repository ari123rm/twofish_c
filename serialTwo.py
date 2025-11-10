import serial
import time

ser = serial.Serial("COM8", 115200, timeout=1)

# 1. Ler entrada.txt
with open("entrada.txt", "r") as f:
    texto = f.read()

# 2. Converter para ASCII e enviar
vetor = [ord(c) for c in texto]
ser.write(bytes(vetor))

time.sleep(0.05)

# 3. Ler resposta (até 8192 bytes)
resposta = ser.read(8192)


# salva no arquivo
with open("cifra.txt", "w") as f:
    f.write(str(resposta))

print("Arquivo cifra.txt gerado com sucesso!")

ser.close()
