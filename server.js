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
  if (!captcha) return res.render('index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${CONFIG.RECAPTCHA_SECRET}&response=${captcha}`;
    const response = await axios.post(verifyUrl);
    if (!response.data.success) return res.render('index', { erro: 'Falha na verificação do reCAPTCHA.', query: {} });

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
  if (!req.session.email) return res.redirect('/login');
  try {
    const emailHash = crypto.createHash('sha256').update(req.session.email).digest('hex');
    await query('UPDATE users SET two_factor_enabled = 1 WHERE email_hash = ?', [emailHash]);
    res.render('enable-2fa', { mensagem: '2FA ativado com sucesso.' });
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).send('Erro ao ativar 2FA');
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

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}.`);
});
