Olá, instale o python utilizando o roteiro neste site: https://linuxize.com/post/how-to-install-python-3-7-on-ubuntu-18-04/
ou coloque os comandos:
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.7

Abra a configuração de conexão e selecione:
>Configuração manual de proxy
>proxy HTTP: IP = '127.0.0.1' e Porta = 33333

Abra o programa .py cmd e pronto o servidor Proxy HTTP
Os arquivos .txt tem que existir na pasta do programa, se quiser alterar quais sites são blacklist ou whitelist
ou quais são os DenyTerm só alterar o conteúdo dos arquivos .txt, um termo por linha OBRIGATORIAMENTE.