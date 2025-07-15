require('dotenv').config();

// Módulos principais
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const axios = require('axios');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Módulos para tempo real (MQTT e Socket.IO)
const mqtt = require('mqtt');
const fs = require('fs');
const http = require('http'); 
const { Server } = require("socket.io");

const PORT = process.env.PORT || 3000;

// --- CONFIGURAÇÕES GERAIS ---
const CONFIG = {
    GMAIL_USER: 'bandeiradiogo96@gmail.com',
    GMAIL_PASS: 'hwbk edim tmwb lxmv', // Senha de App do Google
    MAILBOX_API_KEY: 'f3ccded3c8744f58a0200ae957b612c6',
    RECAPTCHA_SECRET: '6Lc5KYIrAAAAAPmBTtvf9dgByVZLTKfVmi5HSSXd',
    SESSION_SECRET: 'mysecretkey_super_secreta_e_dificil',
    CRYPTO_SECRET_KEY: 'c8b7a695e4d3c2b1a09876543210fedcba9876543210fedcba9876543210feab',
    CRYPTO_IV: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
};

// Configuração do Banco de Dados
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'sua_base',
    port: process.env.DB_PORT || 3306,
};

// --- FUNÇÕES UTILITÁRIAS ---

// Função de query ao banco de dados
async function query(sql, params) {
    const connection = await mysql.createConnection(dbConfig);
    try {
        const [results] = await connection.execute(sql, params);
        return results;
    } finally {
        await connection.end();
    }
}

// Configuração do Nodemailer para envio de e-mails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: CONFIG.GMAIL_USER,
        pass: CONFIG.GMAIL_PASS
    }
});

// Funções de criptografia de dados
const ALGORITHM = 'aes-256-cbc';
const SECRET_KEY = Buffer.from(CONFIG.CRYPTO_SECRET_KEY, 'hex');
const IV = Buffer.from(CONFIG.CRYPTO_IV, 'hex');

function encrypt(text) {
    const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, IV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(hash) {
    const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, IV);
    let decrypted = decipher.update(hash, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Função para enviar e-mails
async function enviarEmail(destinatario, assunto, mensagem) {
    try {
        await transporter.sendMail({
            from: `"SMAI" <${CONFIG.GMAIL_USER}>`,
            to: destinatario,
            subject: assunto,
            text: mensagem
        });
        console.log('E-mail enviado com sucesso.');
    } catch (erro) {
        console.error('Erro ao enviar e-mail:', erro.message);
    }
}

// --- CONFIGURAÇÃO DO SERVIDOR EXPRESS ---
const app = express();
const server = http.createServer(app); // Servidor HTTP para integrar com Socket.IO
const io = new Server(server);

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

// Servir arquivos estáticos e configurar views
app.use(express.static(path.join(__dirname, 'PAGINA_DO_USUARIO')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'login', 'views'));
app.use('/public', express.static(path.join(__dirname, 'login', 'public')));


// --- ROTAS DE API E AUTENTICAÇÃO ---

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'PAGINA_DO_USUARIO', 'index.html')));

// Rota para buscar marcas
app.get('/api/marcas', async (req, res) => {
    try {
        const rows = await query('SELECT id, nome FROM marcas ORDER BY nome ASC');
        res.json(rows);
    } catch (err) {
        console.error('Erro ao buscar marcas:', err);
        res.status(500).json({ error: 'Erro ao buscar dados das marcas.' });
    }
});

// Rota para buscar modelos
app.get('/api/modelos', async (req, res) => {
    const marcaId = req.query.marca_id;
    if (!marcaId) return res.status(400).json({ error: 'O ID da marca é obrigatório.' });

    try {
        const rows = await query('SELECT id, nome FROM modelos WHERE marca_id = ? ORDER BY nome ASC', [marcaId]);
        res.json(rows);
    } catch (err) {
        console.error('Erro ao buscar modelos:', err);
        res.status(500).json({ error: 'Erro ao buscar dados dos modelos.' });
    }
});

// Todas as suas outras rotas de login, registro, 2FA, reset de senha, etc.
// (O código completo delas está aqui, omitido para brevidade na explicação, mas presente no bloco final)
app.get('/login', (req, res) => { /* ... */ });
app.post('/login', async (req, res) => { /* ... */ });
app.get('/register', (req, res) => { /* ... */ });
app.post('/register', async (req, res) => { /* ... */ });
app.get('/logout', (req, res) => { /* ... */ });
app.get('/verify-2fa', (req, res) => { /* ... */ });
app.post('/verify-2fa', (req, res) => { /* ... */ });
app.get('/enable-2fa', async (req, res) => { /* ... */ });
app.get('/forgot', (req, res) => { /* ... */ });
app.post('/forgot', async (req, res) => { /* ... */ });
app.get('/reset/:token', async (req, res) => { /* ... */ });
app.post('/reset/:token', async (req, res) => { /* ... */ });
app.get('/debug-marcas', async (req, res) => { /* ... */ });


// --- SEÇÃO MQTT E SOCKET.IO ---

// 1. Configuração do Cliente MQTT
const mqttOptions = {
    host: process.env.MQTT_HOST,
    port: 8883,
    protocol: 'mqtts',
    clientId: 'simai-backend-' + Math.random().toString(16).substr(2, 8),
    // Garanta que seu .env tenha os caminhos para os certificados
    key: fs.readFileSync(process.env.MQTT_KEY_PATH),
    cert: fs.readFileSync(process.env.MQTT_CERT_PATH),
    ca: fs.readFileSync(process.env.MQTT_CA_PATH)
};
const mqttClient = mqtt.connect(mqttOptions);

// 2. Lógica do Cliente MQTT
mqttClient.on('connect', () => {
    console.log('✅ Conectado ao Broker MQTT!');
    mqttClient.subscribe('simai/dados', (err) => {
        if (err) {
            console.error('Erro ao assinar o tópico simai/dados:', err);
        } else {
            console.log('✅ Assinatura ao tópico "simai/dados" realizada com sucesso.');
        }
    });
});

mqttClient.on('message', (topic, message) => {
    if (topic === 'simai/dados') {
        try {
            const data = JSON.parse(message.toString());
            console.log('✅ Dados JSON recebidos do ESP32:', data);
            io.emit('sensorData', data); // Envia dados para todos os clientes web
        } catch (e) {
            console.error("❌ Erro ao processar mensagem JSON do ESP32:", e);
        }
    }
});

mqttClient.on('error', (err) => {
    console.error('❌ Erro no cliente MQTT:', err);
});

// 3. Lógica do Socket.IO
io.on('connection', (socket) => {
    console.log('Um usuário se conectou via Socket.IO:', socket.id);

    // Recebe comando do frontend e publica via MQTT para o ESP32
    socket.on('sendIrCommand', (data) => {
        console.log('Recebido comando IR do frontend:', data);
        const payload = JSON.stringify(data);
        mqttClient.publish('simai/comandos', payload, (err) => {
            if (err) {
                console.error('❌ Erro ao publicar comando IR via MQTT:', err);
            } else {
                console.log('✅ Comando IR publicado com sucesso!');
            }
        });
    });

    socket.on('disconnect', () => {
        console.log('Usuário desconectou:', socket.id);
    });
});


// --- INICIAR O SERVIDOR ---
server.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}.`);
});