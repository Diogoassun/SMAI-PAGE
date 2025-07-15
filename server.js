// server.js

require('dotenv').config();

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
const PORT = process.env.PORT || 3000;


const mqtt = require('mqtt');
const fs = require('fs');
const http = require('http'); 
const { Server } = require("socket.io");

// --- CONFIGURAÇÕES ---
const CONFIG = {
  PORT: process.env.PORT || 3001,
  GMAIL_USER: 'bandeiradiogo96@gmail.com',
  GMAIL_PASS: 'hwbk edim tmwb lxmv', // Use senha de app do Google
  MAILBOX_API_KEY: 'f3ccded3c8744f58a0200ae957b612c6',
  RECAPTCHA_SECRET: '6Lc5KYIrAAAAAPmBTtvf9dgByVZLTKfVmi5HSSXd',
  SESSION_SECRET: 'mysecretkey_super_secreta_e_dificil',
  CRYPTO_SECRET_KEY: 'c8b7a695e4d3c2b1a09876543210fedcba9876543210fedcba9876543210feab',
  CRYPTO_IV: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
};

// Configuração do banco (puxe do seu .env ou configure aqui)
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'sua_base',
  port: process.env.DB_PORT || 3306,
};



// Função para query simplificada com conexão automática
async function query(sql, params) {
  const connection = await mysql.createConnection(dbConfig);
  try {
    const [results] = await connection.execute(sql, params);
    return results;
  } finally {
    await connection.end();
  }
}

// Setup nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: CONFIG.GMAIL_USER,
    pass: CONFIG.GMAIL_PASS
  }
});

// Funções de criptografia
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

async function enviarEmail(destinatario, assunto, mensagem) {
  try {
    const info = await transporter.sendMail({
      from: `"SMAI" <${CONFIG.GMAIL_USER}>`,
      to: destinatario,
      subject: assunto,
      text: mensagem
    });
    console.log('E-mail enviado: %s', info.messageId);
  } catch (erro) {
    console.error('Erro ao enviar e-mail:', erro.message);
  }
}

// --- APP SETUP ---
const app = express();

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// Serve arquivos estáticos (pode mudar para sua pasta real)
app.use(express.static(path.join(__dirname, 'PAGINA_DO_USUARIO')));

// -- ROTAS DE API --

// Teste raiz - serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'PAGINA_DO_USUARIO', 'index.html'));
});

// Buscar marcas
app.get('/api/marcas', async (req, res) => {
  try {
    const rows = await query('SELECT id, nome FROM marcas ORDER BY nome ASC');
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar marcas:', err);
    res.status(500).json({ error: 'Erro ao buscar dados das marcas.' });
  }
});

// Buscar modelos por marca
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

// Controle manual (exemplo)
app.post('/api/control', async (req, res) => {
  const { comando, marcaId, modeloId } = req.body;
  if (!comando || !marcaId || !modeloId) {
    return res.status(400).json({ message: 'Informações incompletas.' });
  }
  console.log(`Comando recebido: '${comando}' | Marca ID: ${marcaId} | Modelo ID: ${modeloId}`);
  // Aqui entra a lógica do seu controle IR
  res.status(200).json({ message: `Comando '${comando}' processado!` });
});

// --- ROTAS DE AUTENTICAÇÃO, SESSÃO, 2FA, REGISTRO, RESET ---

// View engine (se usar ejs)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'login', 'views'));
app.use('/public', express.static(path.join(__dirname, 'login', 'public')));

// Rota Home/Login
app.get('/login', (req, res) => {
  if (req.session.email) {
    return res.render('index', { email: req.session.email });
  }
  res.render('index', { erro: null, query: req.query || {} });
});

// Login POST
app.post('/login', async (req, res) => {
  const { email, password, 'g-recaptcha-response': captcha } = req.body;
 // if (!captcha) return res.render('index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });

  try {
    /*const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${CONFIG.RECAPTCHA_SECRET}&response=${captcha}`;
    const response = await axios.post(verifyUrl);
    if (!response.data.success) return res.render('index', { erro: 'Falha na verificação do reCAPTCHA.', query: {} });
    */
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const users = await query('SELECT * FROM users WHERE email_hash = ?', [emailHash]);

    if (users.length > 0) {
      const user = users[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const decryptedEmail = decrypt(user.email);
        if (user.two_factor_enabled) {
          const codigo = Math.floor(100000 + Math.random() * 900000);
          req.session.pendingUser = decryptedEmail;
          req.session.verificationCode = codigo;
          req.session.verificationExpires = Date.now() + 5 * 60 * 1000;
          await enviarEmail(decryptedEmail, 'Código de Verificação 2FA', `Seu código de verificação é: ${codigo}`);
          return res.redirect('/verify-2fa');
        }
        req.session.email = decryptedEmail;
        return res.redirect('/presentation.html');
      }
    }
    return res.render('index', { erro: 'E-mail ou senha incorretos', query: {} });

  } catch (err) {
    console.error('Erro no login:', err); // mostra o erro completo
    return res.status(500).send('Erro no servidor durante o login.');
  }
});

// Registro GET
app.get('/register', (req, res) => res.render('register'));

// Registro POST
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Preencha o e-mail e a senha');

  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.status(400).send('Formato de e-mail inválido');

  try {
    // Validação com API Abstract
    const apiKey = CONFIG.MAILBOX_API_KEY;
    const response = await axios.get(`https://emailvalidation.abstractapi.com/v1/?api_key=${apiKey}&email=${email}`);

    if (response.data.deliverability === "UNDELIVERABLE" || response.data.is_disposable_email.value === true) {
      return res.status(400).send('Este endereço de e-mail não é válido ou não é permitido.');
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const encryptedEmail = encrypt(email);
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');

    await query(
      'INSERT INTO users (email, password, email_hash) VALUES (?, ?, ?)',
      [encryptedEmail, hashedPassword, emailHash]
    );

    await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');
    res.redirect('/login?cadastro=sucesso');

  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).send('Este e-mail já está cadastrado');
    }
    console.error('Erro ao cadastrar:', err.message || err);
    res.status(500).send('Erro ao cadastrar usuário');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Não foi possível fazer logout.');
    res.redirect('/login');
  });
});

// 2FA verify GET
app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/login');
  res.render('verify-2fa', { erro: null });
});

// 2FA verify POST
app.post('/verify-2fa', (req, res) => {
  const { code } = req.body;
  if (!req.session.verificationCode || Date.now() > req.session.verificationExpires) {
    return res.render('verify-2fa', { erro: 'Código expirado. Faça login novamente.' });
  }
  if (parseInt(code) === req.session.verificationCode) {
    req.session.email = req.session.pendingUser;
    delete req.session.pendingUser;
    delete req.session.verificationCode;
    delete req.session.verificationExpires;
    return res.redirect('/presentation.html');
  } else {
    return res.render('verify-2fa', { erro: 'Código incorreto. Tente novamente.' });
  }
});

// Ativar 2FA
app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) {
    return res.status(401).json({ error: 'Usuário não autenticado.' });
  }
  try {
    const emailHash = crypto.createHash('sha256').update(req.session.email).digest('hex');
    await query('UPDATE users SET two_factor_enabled = 1 WHERE email_hash = ?', [emailHash]);
    res.json({ mensagem: '2FA ativado com sucesso!' }); // <-- Retorna JSON
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).json({ error: 'Erro interno ao ativar 2FA.' });
  }
});

// --- Reset senha ---

// Form solicitar reset
app.get('/forgot', (req, res) => {
  res.render('forgot', { erro: null, sucesso: null });
});

// POST solicitar reset
app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  try {
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const users = await query('SELECT id FROM users WHERE email_hash = ?', [emailHash]);

    if (users.length === 0) {
      // Mensagem genérica para segurança
      return res.render('forgot', {
        erro: null,
        sucesso: 'Se um utilizador com este e-mail existir, um link de redefinição foi enviado.'
      });
    }

    const user = users[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

    await query(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [token, expires, user.id]
    );

    const resetLink = `http://${req.headers.host}/reset/${token}`;
    await enviarEmail(email, 'Redefinição de Senha', `Clique para redefinir sua senha: ${resetLink}`);

    res.render('forgot', {
      erro: null,
      sucesso: 'Se um utilizador com este e-mail existir, um link de redefinição foi enviado.'
    });

  } catch (err) {
    console.error('Erro em /forgot:', err);
    res.render('forgot', {
      sucesso: null,
      erro: 'Ocorreu um erro interno. Tente novamente.'
    });
  }
});

// Form reset senha
app.get('/reset/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const rows = await query(
      'SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()',
      [token]
    );

    if (rows.length === 0) {
      return res.status(400).send('O link de redefinição de senha é inválido ou expirou.');
    }

    res.render('reset', { erro: null, token });

  } catch (err) {
    console.error('Erro em /reset/:token:', err);
    res.status(500).send('Erro interno.');
  }
});

// POST reset senha
app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

 // if (password !== confirmPassword) {
  //  return res.render('reset', { erro: 'As senhas não coincidem.', token });
 // }

  try {
    const rows = await query(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()',
      [token]
    );

    if (rows.length === 0) {
      return res.status(400).send('O link de redefinição de senha é inválido ou expirou.');
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await query(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = ?',
      [hashedPassword, token]
    );

    res.redirect('/login?redefinicao=sucesso');

  } catch (err) {
    console.error('Erro em /reset/:token POST:', err);
    res.status(500).send('Erro ao redefinir senha.');
  }
});

app.get('/debug-marcas', async (req, res) => {
  let connection;
  try {
    // 1. Conecta ao banco de dados
    connection = await mysql.createConnection(dbConfig);

    // 2. Executa a consulta exata para buscar as marcas
    const [marcas] = await connection.execute('SELECT id, nome FROM marcas ORDER BY nome ASC');

    // 3. Verifica o resultado e mostra na tela
    if (marcas.length === 0) {
      // Caso a consulta funcione mas não retorne nenhuma linha
      res.status(200).send(`
        <h1>🟡 Consulta bem-sucedida, mas a tabela 'marcas' está vazia.</h1>
        <p>A conexão com o banco de dados e a consulta SQL funcionaram corretamente.</p>
        <p>O problema é que não há nenhum registro na sua tabela <strong>marcas</strong>.</p>
        <p><strong>Solução:</strong> Adicione algumas marcas à sua tabela no MySQL (usando phpMyAdmin, por exemplo) e tente novamente.</p>
      `);
    } else {
      // Caso encontre marcas, exibe em uma tabela
      res.status(200).send(`
        <h1>✅ Marcas encontradas com sucesso!</h1>
        <p>Foram encontrados <strong>${marcas.length}</strong> registros na tabela 'marcas'.</p>
        <p>Isso confirma que seu backend está buscando os dados corretamente. Se eles não aparecem na página principal, o erro está no seu código <strong>Frontend</strong> (JavaScript).</p>
        <hr>
        <h2>Dados Retornados:</h2>
        <table border="1" cellpadding="5" cellspacing="0">
          <thead>
            <tr>
              <th>ID</th>
              <th>Nome</th>
            </tr>
          </thead>
          <tbody>
            ${marcas.map(marca => `<tr><td>${marca.id}</td><td>${marca.nome}</td></tr>`).join('')}
          </tbody>
        </table>
        <hr>
        <h3>Dados em formato JSON (bruto):</h3>
        <pre>${JSON.stringify(marcas, null, 2)}</pre>
      `);
    }

  } catch (err) {
    // Se a consulta falhar (ex: tabela não existe)
    console.error('ERRO AO BUSCAR MARCAS (DEBUG):', err);
    res.status(500).send(`
        <h1>❌ Falha ao buscar dados da tabela 'marcas'</h1>
        <p>A conexão com o banco de dados pode estar funcionando, mas a consulta à tabela <strong>marcas</strong> falhou.</p>
        <p><strong>Causa provável:</strong> A tabela 'marcas' não existe no banco de dados '${dbConfig.database}' ou o nome da tabela/colunas está incorreto.</p>
        <hr>
        <h2>Detalhes do Erro:</h2>
        <pre style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap;"><code>${err.stack}</code></pre>
    `);
  } finally {
    // Garante que a conexão seja sempre fechada
    if (connection) {
      await connection.end();
    }
  }
});

const server = http.createServer(app);
const io = new Server(server);

// --- INÍCIO DA SEÇÃO MQTT E SOCKET.IO ---

// 1. CONFIGURAÇÃO DO CLIENTE MQTT
// ==============================================================
const options = {
  host: process.env.MQTT_HOST,
  port: 8883,
  protocol: 'mqtts',
  clientId: 'simai-backend-' + Math.random().toString(16).substr(2, 8),
  // GARANTA QUE SEU .env TENHA OS NOMES COM _PATH NO FINAL
  key: fs.readFileSync(process.env.MQTT_KEY_PATH),
  cert: fs.readFileSync(process.env.MQTT_CERT_PATH),
  ca: fs.readFileSync(process.env.MQTT_CA_PATH)
};

const mqttClient = mqtt.connect(options);

// 2. LÓGICA DO CLIENTE MQTT (O QUE FAZER AO CONECTAR, RECEBER MENSAGEM, ETC)
// ==============================================================
mqttClient.on('connect', () => {
  console.log('✅ Conectado ao Broker MQTT!');
  // Assina o tópico para receber dados JSON do ESP32
  mqttClient.subscribe('simai/dados', (err) => {
    if (err) {
      console.error('Erro ao assinar o tópico simai/dados:', err);
    } else {
      console.log('✅ Assinatura ao tópico "simai/dados" realizada com sucesso.');
    }
  });
});

// LÓGICA CORRETA PARA RECEBER JSON DO ESP32
mqttClient.on('message', (topic, message) => {
    if (topic === 'simai/dados') { 
        try {
            const data = JSON.parse(message.toString());
            console.log('✅ Dados JSON recebidos do ESP32:', data);
            io.emit('sensorData', data); 
        } catch (e) {
            console.error("❌ Erro ao processar mensagem JSON do ESP32:", e);
        }
    }
});

mqttClient.on('error', (err) => {
  console.error('❌ Erro no cliente MQTT:', err);
});

// 3. LÓGICA DO SOCKET.IO (O QUE FAZER QUANDO UM USUÁRIO CONECTA PELO NAVEGADOR)
// ==============================================================
io.on('connection', (socket) => {
    console.log('Um usuário se conectou via Socket.IO:', socket.id);

    // LÓGICA CORRETA PARA ENVIAR COMANDOS PARA O ESP32
    socket.on('sendIrCommand', (data) => {
      console.log('Recebido comando IR do frontend:', data);
      const payload = JSON.stringify(data);

      // Publica no tópico padronizado correto
      mqttClient.publish('simai/comandos', payload, (err) => {
        if (err){
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

// --- FIM DA SEÇÃO MQTT E SOCKET.IO ---

server.listen({
    host: '0.0.0.0',
    port: PORT
},() => {
  console.log(`Servidor rodando na porta ${PORT}.`);
});