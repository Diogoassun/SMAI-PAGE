# Sistema de Monitoramento Ambiental Inteligente (SMAI)

![Status](https://img.shields.io/badge/status-Em%20Desenvolvimento-yellow)
![Versão](https://img.shields.io/badge/version-1.0.0-blue)
![Licença](https://img.shields.io/badge/license-MIT-green)

Um sistema completo para monitoramento ambiental em tempo real e controle de climatização, utilizando uma rede de sensores sem fio e uma interface web interativa.

---

## 📖 Tabela de Conteúdos

- [🌟 Sobre o Projeto](#-sobre-o-projeto)
- [✨ Principais Funcionalidades](#-principais-funcionalidades)
- [🏗️ Arquitetura do Sistema](#-arquitetura-do-sistema)
- [🚀 Tecnologias Utilizadas](#-tecnologias-utilizadas)
- [🛠️ Como Começar](#️-como-começar)
  - [Pré-requisitos](#pré-requisitos)
  - [Instalação](#instalação)
- [📱 Uso](#uso)
- [🤝 Como Contribuir](#-como-contribuir)
- [📄 Licença](#-licença)

---

## 🌟 Sobre o Projeto

O **Sistema de Monitoramento Ambiental Inteligente (SMAI)** foi desenvolvido para monitorar variáveis ambientais como temperatura, pressão e umidade em múltiplos pontos de um ambiente, como uma sala de aula.

O objetivo é fornecer dados precisos e em tempo real para otimizar o conforto térmico e a eficiência energética através do controle inteligente de um sistema de ar-condicionado.

O projeto é composto por três pilares principais:

1. **Nós Sensores:** Microcontroladores **STM32F103C8T6** com sensores e módulos **NRF24L01** para coleta e envio de dados.
2. **Nó Central:** Também baseado em STM32 + NRF24L01, com interface IR para controlar o ar-condicionado.
3. **Sistema Web:** Interface moderna com gráficos e controle remoto, acessível via navegador.

---

## ✨ Principais Funcionalidades

- 🛰️ Monitoramento Distribuído por múltiplos sensores
- 📡 Comunicação Sem Fio com NRF24L01
- ❄️ Controle de Climatização via IR para ar-condicionado
- 📊 Dashboard com Atualização em Tempo Real
- 🔒 Login com autenticação e 2FA opcional
- 🕓 Histórico de dados e exportação de relatórios

---

## 🏗️ Arquitetura do Sistema

```text
[Nó Sensor 1] ----╮
[Nó Sensor 2] ----┤     (NRF24L01)     [Nó Central] <---- MQTT/Socket.IO ----> [Sistema Web]
[Nó Sensor N] ----╯                     (STM32 + IR)                           (Node.js + EJS)
                                             |
                                    (Infravermelho) ---> [Ar-Condicionado]
🚀 Tecnologias Utilizadas
🔧 Hardware
STM32F103C8T6 (Blue Pill)

NRF24L01+

Sensores: BME280 ou DHT22

Controle Infravermelho

🧠 Firmware (Embarcado)
Linguagem: C/C++

Ambiente: STM32CubeIDE ou PlatformIO

Bibliotecas: HAL, RF24, IRremote

🖥️ Backend
Node.js + Express.js

Banco de Dados: MySQL

Comunicação: MQTT + Socket.IO

Autenticação: bcrypt, express-session

🌐 Frontend
HTML5 + CSS3 + JavaScript

Template Engine: EJS

Gráficos: Chart.js e Plotly.js

🛠️ Como Começar
Pré-requisitos
Node.js (v16+)

Git

STM32CubeIDE ou PlatformIO

MySQL Server

Broker MQTT (Mosquitto, HiveMQ, etc.)

Instalação
1. Clone o repositório
bash
Copiar
Editar
git clone https://github.com/seu-usuario/smai-projeto.git
cd smai-projeto
2. Configure o Backend
bash
Copiar
Editar
cd backend
npm install
cp .env.example .env
Preencha o arquivo .env com suas credenciais:

env
Copiar
Editar
# Banco de Dados
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=sua_senha
DB_NAME=smai_db
DB_PORT=3306

# MQTT
MQTT_HOST=broker.exemplo.com
MQTT_PORT=8883
MQTT_KEY_PATH=./certs/private.key
MQTT_CERT_PATH=./certs/certificate.crt
MQTT_CA_PATH=./certs/ca_bundle.crt
Depois, inicie o servidor:

bash
Copiar
Editar
npm start
3. Configure o Firmware
Abra o projeto no STM32CubeIDE ou PlatformIO

Ajuste os pinos de comunicação com NRF24L01

Compile e grave nos dispositivos

📱 Uso
Acesse: http://localhost:3000

Crie uma conta e faça login

Visualize os sensores conectados em tempo real

Acesse gráficos e relatórios

Controle o ar-condicionado remotamente via interface web

🤝 Como Contribuir
Contribuições são sempre bem-vindas! Siga os passos abaixo:

bash
Copiar
Editar
# 1. Faça um fork do projeto
# 2. Crie uma branch para sua feature
git checkout -b minha-feature

# 3. Faça commit das suas alterações
git commit -m 'Minha nova feature'

# 4. Faça push para a branch
git push origin minha-feature

# 5. Abra um Pull Request
📄 Licença
Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para mais detalhes.
