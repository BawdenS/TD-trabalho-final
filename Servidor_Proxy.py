import time
import sys
import socket
import threading
from threading import *

# Variaveis Globais correspondendo as listas WhiteList, BlackList e DenyTerms
global BlackL
BlackL = []
# Cria uma lista a partir dos dominios não permitidos
with open("BlackList.txt", "r") as f:
    for line in f:
        BlackL.append(line)

global WhiteL
WhiteL = []
# Cria uma lista a partir dos dominios permitidos
with open("WhiteList.txt", "r") as f:
    for line in f:
        WhiteL.append(line)
            
global DenyTerms
DenyTerms = []
# Cria uma lista a partir dos termos banidos
with open("DenyTerm.txt", "r") as f:
    for line in f:
        DenyTerms.append(line)


# Função que pega todas as informações necessárias para identificar o destino
# da requisição do cliente
def connection_info (conn, addr, data):
    try:
        #Pega a URL do segmento HTTP recebido pelo cliente
        first_line = data.split('\n')[0]    # Pega a primeira string gerada pelo data.split()
        url = first_line.split(' ')[1]      # Pega a segunda string gerada pelo first_line.split()

        http_pos = url.find("://")      # Encontra posição de '://'
        if (http_pos == -1):
            temp = url
        else:
            temp = url[(http_pos+3):]   # Pega o resto da URL

        port_pos = temp.find(":")       # Encontra posição da porta (se houver)

        # Encontra fim do webserver
        webserver_pos = temp.find("/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        webserver = ""
        port = -1
        if (port_pos == -1 or webserver_pos < port_pos): 
            port = 80       # Porta padrão
            webserver = temp[:webserver_pos] 

        else:               # Porta específica 
            port = int((temp[(port_pos+1):])[:webserver_pos-(port_pos+1)])
            webserver = temp[:port_pos]

        print("\n\rWebServer: {}\n\rPorta: {}".format(webserver,port))

        # Verifica se o dominio requisitado encontra-se na blacklist ou whitelist
        # se nao estiver em nenhum, verifica se há DenyTerms
        response = VerificaList(webserver, BlackL, WhiteL)
        
        if (response == "WHITE"):
            with open("log.txt", 'a') as f:
                tempo = time.ctime(seconds)
                f.write("Dominio: " + webserver + ". " + str(time.time()) + "segundos. Acesso permitido. \n")

            deny = 0
            proxy_server(webserver, port, conn, addr, data, deny)
            
        elif (response == "BLACK"):
            with open("log.txt", 'a') as f:
                f.write("Dominio: " + webserver + ". " + str(time.time()) + "segundos. Acesso negado por blacklist. \n")
            conn.send("Acesso nao Permitido!\nMotivo: BLACK LIST.".encode("utf-8"))
            conn.close()

        elif (response == "DENY"):
            # Procura DenyTerms na requisicação do cliente
            for termos in DenyTerms:
                if data.find(termos[:len(termos)-1]) != -1:
                    with open("log.txt", 'a') as f:
                        f.write("Dominio: " + webserver + ". " + str(time.time()) + "segundos. acesso negado por DenyTerm. \n")
                    conn.send("Acesso nao Permitido!\nMotivo: DENY TERM.".encode("utf-8"))
                    conn.close()
                    
            # Procura DenyTerms na resposta do servidor requisitado pelo cliente
            deny = 1
            proxy_server(webserver, port, conn, data, deny)
            
        
    except Exception:
        pass


# Aqui o servidor proxy manda o requerimento do cliente ao servidor de destino
# e em seguida manda a resposta ao cliente
def proxy_server (webserver, port, conn, addr, data, deny):
    request_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    request_socket.connect((webserver, port))
    request_socket.settimeout(20)
    request_socket.sendall(data.encode())

    while True:
        # Recebe Mensagem do servidor web
        msg = request_socket.recv(4096)
        # deny = 0 para endereços da Whitelist
        if (deny == 0):
            # Envia msg a cliente, enquanto houver msg
            if(len(msg) > 0):
                conn.send(msg)
            else:
                print(msg)
                request_socket.close()
                conn.close()
                break
        # deny = 1 para endereços nao pertencentes a whitelist nem blacklist
        elif(deny == 1):
            # Confere se há palavra proibida
            for i in range (0,len(DenyTerms)):
                if (DenyTerms[i] in msg):
                    conn.send("Acesso nao Permitido!\nMotivo: DENY TERM.".encode("utf-8"))
                    conn.close()
            break

    # Encerra conexao com o servidor web
    request_socket.close()
    conn.close()
        

# Função que analisa o dominio requerido e verifica se é permitido ou não
def VerificaList(webserver, BlackL, WhiteL):
    i = 0
    j = 0
    for dominio_b in BlackL:
        if webserver.find(dominio_b[:len(dominio_b)-1]) != -1:
            i = 1
            print ("Acesso Negado!!!")
            return "BLACK"

    for dominio_w in WhiteL:
        if webserver.find(dominio_w[:len(dominio_w)-1]) != -1:
            j = 1
            print ("Site Liberado!!!")
            return "WHITE"

    if (i == 0 and j == 0):
        return "DENY"

# Função Principal
def Main():

    # Para criar o servidor proxy é necessário criar um socket para ele
    try:
        host = '127.0.0.1'      # Endereço IP de loopback
        port = 33333

        # Cria um socket do tipo IPv4 e conexão TCP/IP
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)		 
        print ("Socket successfully created")
        # Liga o socket à porta especificada, mas a nenhum endereço especifico
        s.bind(('', port))		 
        print ("Socket binded to {}".format(port))
        # Escuta através da porta especificada qualquer requisição de qlqr endereço
        # possuindo uma fila de até 5 clientes
        s.listen(5)	 
        print ("Socket is listening...")
        
    except Exception:
        print ("Nao foi possivel iniciar o socket!!\n")
        sys.exit(1)

    while True: 
        try:
            # Estabele conexão com o cliente.
            conn, addr = s.accept()
            print ("\n------------------------------------------")
            print ("\n\rGot connection from {}".format(addr))
            data = conn.recv(4096).decode("utf-8","ignore")
            # Manda para uma thread, assim o servidor pode receber outras conexões
            t = threading.Thread(target=connection_info,args=(conn,addr,data))
            t.setDaemon(True)
            t.start()
            
        except KeyboardInterrupt:
            print ("Detectada uma interrupcao pelo teclado.\n")
            print ("Desligando servidor...\n")
            s.close()
            sys.exit(2)

    s.close()


if __name__ == "__main__":
	Main()
