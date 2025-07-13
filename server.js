import express from 'express'
import path from 'path'
import {fileURLToPath} from 'url'
import jwt from 'jsonwebtoken'

import dotenv from 'dotenv'
dotenv.config(); // Carrega as variáveis de ambiente do arquivo .env
import mysql from 'mysql2'
// const db = require('./mysql'); // Este arquivo ainda lida com a conexão do DB
import axios from 'axios'
import bodyParser from 'body-parser'
import session from 'express-session'
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt'
import crypto from 'crypto'


import cookieParser from 'cookie-parser';

import authRouter from './routes/authRoutes.js';


const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express();

app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '/views'));
app.use(express.static(path.join(__dirname, '/public')));
// app.use('public', express.static(path.join(__dirname, '/public')));

// rota estática

/*
app.use(session({
    secret: process.env.SESSION_SECRET,
    // ... o resto da sua configuração de sessão
}));
*/

// Middleware de Logger
const logger = (req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next(); // Essencial! Passa para o próximo da fila.
};

// Use o middleware na sua aplicação
app.use(logger);


// 3. MIDDLEWARE
// ==========================================
// Configurar o body-parser para lidar com dados de formulário
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser()); // Middleware para interpretar cookies

// ROTA DE TESTE
const users = [
    {id: 1, username: 'leo', password: '123456', role: 'admin'},
    {id: 2, username: 'oel', password: '654321', role: 'user'}
]


/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/
/**/

// ROTA ENVIAR

function checkAuth(req, res, next) {
    next();
    if (req.session.user) {
        return next(); // Autenticado, pode continuar
    }
    // Não autenticado! Redireciona para o login com a URL original
    const redirectUrl = encodeURIComponent(req.originalUrl); // ex: /pedidos
    console.log('error');
    res.redirect(`/login?redirectUrl=${redirectUrl}`);
}

// app.get('/pedidos', checkAuth, (req, res) => { /* ... */ });


app.get('/sign-in-ejs', (req, res) =>{
    res.render(path.join('public','index.ejs'));
});
/*
/
/siggn-in
/register
/dashboard
/profile
/settings
*/
// app.use('/assets', express.static(path.join(__dirname, 'login-node-main', 'public')));

app.post('/enviar', checkAuth, (req, res) => {
    const { email, password } = req.body;
    console.log('tstesssssssssssssssssssss');
    //const user =  users.find(user => user.user == username && user.password == password);

    if (1){

        const userPayload =  {
            id: 123,
            username: "admin",
            role: "admin"
        };

        const acessToken= jwt.sign(
            userPayload,
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '60s' }
        );

        const refreshToken= jwt.sign(
            userPayload,
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1h' }
        );


        res.status(201).json({
            message: "login bem sucedido",
            tokens: { acessToken, refreshToken },
            userPayload
        });
    }
    else {
        res.status(401).json({
            success: false, 
            message: "usuario não é válido"
        });
    }
})

// ROTA DE TESTE

// ROTAS
app.use('/sobre', authRouter);

app.get('/status', (request, response) => {
    console.log('✅ Rota /status foi chamada!');
    response.json({
        status: "OK",
        message: "Servidor está funcionando perfeitamente!",
        timestamp: new Date().toISOString()
    });
});

// app.get('/', (resquest, response) => {
//     return response.send('<h1>hello</h1>')
// })

app.get('/about', (resquest, response) => {
    return response.send('<h1>about</h1>')
})

// app.listen({
//     host: '0.0.0.0',
//     port: 3333
// })


/* <----> */
// 1. IMPORTAÇÕES E CONFIGURAÇÃO INICIAL
// ==========================================

const port = process.env.PORT;

// 2. CONFIGURAÇÃO DO BANCO DE DADOS (APENAS UMA VEZ!)
// ====================================================
const dataBase = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Conectar ao banco de dados
dataBase.connect((err) => {
  if (err) {
    console.error('!!!!!!!!!! ERRO AO CONECTAR AO BANCO DE DADOS !!!!!!!!!!');
    throw err;
  }
  console.log('Conectado ao banco de dados MySQL no AWS RDS!');
});




// Configurar a sessão
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Alterado para false, boa prática para não salvar sessões vazias
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Em produção (HTTPS), será true. Em dev (HTTP), false.
        httpOnly: true // Ajuda a prevenir ataques XSS
    }
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'SITE_CADEIRA_ES', 'index.html'));
});

// 4. ROTAS PÚBLICAS (Login, Registro, Páginas Iniciais)
// =======================================================
/*

// app.get('/sign-in', (req, res) => {
//   res.sendFile(path.join(__dirname, '/public/sign-in/page.html'));
// });

// app.get('/register');

// Rota para o registro de novos usuários
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email e senha são obrigatórios.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';

        dataBase.query(sql, [email, hashedPassword], (err, result) => {
            if (err) {
                console.error('ERRO AO INSERIR NO BANCO DE DADOS:', err);
                return res.status(500).send('Erro ao registrar o usuário. O email já pode estar em uso.');
            }
            console.log('Usuário registrado com sucesso:', result.insertId);
            res.send('Usuário registrado com sucesso! <a href="/">Fazer Login</a>');
        });
    } catch (error) {
        console.error('ERRO NO BCRYPT:', error);
        res.status(500).send('Erro interno no servidor.');
    }
});
*/

// Rota para servir a página de login/registro
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Rota para o processo de login (LÓGICA CORRIGIDA)
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email e senha são obrigatórios.');
    }

    const sql = 'SELECT * FROM users WHERE email = ?';

    dataBase.query(sql, [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Erro no servidor.');
        }

        if (results.length === 0) {
            return res.status(401).send('Email ou senha inválidos.');
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('Email ou senha inválidos.');
        }

        // LÓGICA CORRIGIDA E SIMPLIFICADA
        if (user.is_two_factor_enabled) {
            req.session.pending_2fa_userId = user.id;
            res.json({ success: true, requires2FA: true, redirectTo: '/enter-2fa-token' });
            // res.redirect('/enter-2fa-token');
        } else {
            req.session.userId = user.id;
            req.session.userEmail = user.email;
            res.json({ success: true, requires2FA: false, redirectTo: '/dashboard' });
            // res.redirect('/dashboard');
        }
        // O CÓDIGO CONFLITANTE QUE ESTAVA AQUI FOI REMOVIDO
    });
});

// Rota de logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/sign-in');
    });
});

// 5. ROTAS DE AUTENTICAÇÃO DE DOIS FATORES (2FA)
// =================================================

// Página que pede o token 2FA
app.get('/enter-2fa-token', (req, res) => {
    if (!req.session.pending_2fa_userId) {
        return res.redirect('/erro');
    }
    res.sendFile(__dirname + '/2fa-token-page.html');
});

// Rota que verifica o token 2FA durante o login
app.post('/verify-2fa-login', (req, res) => {
    const userId = req.session.pending_2fa_userId;
    const { token } = req.body;

    if (!userId || !token) {
        return res.redirect('/');
    }

    const sql = 'SELECT * FROM users WHERE id = ?';
    dataBase.query(sql, [userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(500).send('Erro ao buscar usuário.');
        }
        const user = results[0];
        const verified = speakeasy.totp.verify({
            secret: user.two_factor_secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            delete req.session.pending_2fa_userId;
            req.session.userId = user.id;
            req.session.userEmail = user.email;
            res.redirect('/dashboard');
        } else {
            res.status(401).send('Código de dois fatores inválido. <a href="/">Tentar novamente</a>');
        }
    });
});


// 6. ROTAS PROTEGIDAS (PRECISAM DE LOGIN)
// ==========================================

// Middleware para verificar se o usuário está autenticado
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/');
};

app.get('/disable-2fa-page', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/disable-2fa.html');
});

// A rota do painel agora usa o middleware `isAuthenticated`
app.get('/dashboard', isAuthenticated, (req, res) => {
    // Adicione o link para /disable-2fa-page
    res.send(`
        <h1>Painel Secreto</h1>
        <p>Olá, ${req.session.userEmail}!</p>
        <a href="/setup-2fa">Configurar 2FA</a><br>
        <a href="/disable-2fa-page">Desativar 2FA</a><br><br> 
        <a href="/logout">Sair</a>
    `);
});

// Rota para iniciar a configuração do 2FA (precisa estar logado)
app.get('/setup-2fa', isAuthenticated, (req, res) => {
    const secret = speakeasy.generateSecret({
        name: `MeuSuperSite (${req.session.userEmail})`
    });
    req.session.two_factor_temp_secret = secret.base32;

    QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) {
            return res.status(500).send('Erro ao gerar QR Code.');
        }
        res.send(`
            <h1>Configure a Autenticação de Dois Fatores</h1>
            <p>Escaneie o QR Code abaixo com seu app de autenticação.</p>
            <img src="${data_url}">
            <p>Depois, insira o código de 6 dígitos para confirmar.</p>
            <form action="/verify-2fa-setup" method="POST">
                <label for="token">Token:</label>
                <input type="text" name="token" id="token" required>
                <button type="submit">Verificar e Ativar</button>
            </form>
        `);
    });
});



// Rota para verificar e salvar a configuração do 2FA
app.post('/verify-2fa-setup', isAuthenticated, (req, res) => {
    const { token } = req.body;
    const secret = req.session.two_factor_temp_secret;

    if (!secret) {
        return res.redirect('/setup-2fa');
    }

    const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token
    });

    if (verified) {
        const sql = 'UPDATE users SET two_factor_secret = ?, is_two_factor_enabled = TRUE WHERE id = ?';
        dataBase.query(sql, [secret, req.session.userId], (err, result) => {
            if (err) {
                return res.status(500).send('Erro ao salvar configuração.');
            }
            delete req.session.two_factor_temp_secret;
            res.send('2FA ativado com sucesso! <a href="/dashboard">Voltar ao Painel</a>');
        });
    } else {
        res.status(400).send('Código inválido, tente novamente. <a href="/setup-2fa">Gerar novo QR Code</a>');
    }
});

app.post('/disable-2fa', isAuthenticated, (req, res) => { // Removido o 'async' daqui
    const { password } = req.body;
    const userId = req.session.userId;

    if (!password) {
        return res.status(400).send('A senha é obrigatória para confirmar.');
    }

    const getUserSql = 'SELECT * FROM users WHERE id = ?';
    dataBase.query(getUserSql, [userId], async (err, results) => { // o 'async' aqui é o importante
        if (err || results.length === 0) {
            return res.status(500).send('Erro ao encontrar o usuário.');
        }

        try {
            const user = results[0];
            const isMatch = await bcrypt.compare(password, user.password); // 'await' é usado aqui

            if (!isMatch) {
                return res.status(403).send('Senha incorreta. Ação não autorizada.');
            }
            
            // ... resto do código continua igual ...
            const disable2FASql = 'UPDATE users SET is_two_factor_enabled = FALSE, two_factor_secret = NULL WHERE id = ?';
            dataBase.query(disable2FASql, [userId], (disableErr, disableResult) => {
                if (disableErr) {
                    return res.status(500).send('Erro ao desativar a 2FA no banco de dados.');
                }
                res.send('Autenticação de dois fatores desativada com sucesso! <a href="/dashboard">Voltar ao Painel</a>');
            });

        } catch (error) {
            console.error('Erro no processo de desativação de 2FA:', error);
            res.status(500).send('Erro interno do servidor.');
        }
    });
});


/*
*
*
*
*
*
*
*
*/

// --- BLOCO DE CONFIGURAÇÃO (NÃO RECOMENDADO PARA PRODUÇÃO) ---
// Substitua todos os valores abaixo pelos seus.
const CONFIG = {
  PORT: process.env.PORT,
  GMAIL_USER: process.env.GMAIL_USER,
  GMAIL_PASS: process.env.GMAIL_PASS,
  MAILBOX_API_KEY: process.env.MAILBOX_API_KEY,
  RECAPTCHA_SECRET: process.env.RECAPTCHA_SECRET,
  SESSION_SECRET: process.env.SESSION_SECRET,
  // Gere suas próprias chaves! Não use estas.
  CRYPTO_SECRET_KEY: process.env.CRYPTO_SECRET_KEY,
  CRYPTO_IV: process.env.CRYPTO_IV
};
// -------------------------------------------------------------

// const port = CONFIG.PORT || 3000;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: CONFIG.GMAIL_USER,
    pass: CONFIG.GMAIL_PASS
  }
});

// Configuração e Funções de Criptografia
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

// Função de envio de e-mail
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

app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));


// Rota home/login
app.get('/sign-in', (req, res) => {
  if (req.session.email) {
    return res.render('logado', { email: req.session.email });
  }
  res.render('public/sign-in', { erro: null, query: req.query || {} });
});


// Rota de Login com Criptografia
app.post('/sign-in', async (req, res) => {
    const { email, password, 'g-recaptcha-response': captcha } = req.body;
    
    if (!captcha) {
        // return res.render('public/index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });
        return res.json({ success: false, requires2FA: false, redirectTo: '', render: false, message: 'Por favor, confirme que você não é um robô.', query: {} });
    }

    try {
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${CONFIG.RECAPTCHA_SECRET}&response=${captcha}`;
        const response = await axios.post(verifyUrl);
        if (!response.data.success) {
            // res.render('index');
            return res.json({ success: false, requires2FA: false, redirectTo: 'index', render: true, message: 'Falha na verificação do reCAPTCHA.', query: {} });
        }
        const emailHash = crypto.createHash('sha256').update(email).digest('hex');
        const [rows] = await dataBase.execute('SELECT * FROM users WHERE email_hash = ?', [emailHash]);

        if (rows.length > 0) {
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);

        if (match) {
            const decryptedEmail = decrypt(user.email);
            if (user.two_factor_enabled) {
                const codigo = Math.floor(100000 + Math.random() * 900000);
                req.session.pendingUser = decryptedEmail;
                req.session.verificationCode = codigo;
                req.session.verificationExpires = Date.now() + 5 * 60 * 1000;
                await enviarEmail(decryptedEmail, 'Código de Verificação 2FA', `Seu código de verificação é: ${codigo}`);
                // return res.redirect('/verify-2fa');
                return res.json({ success: true, requires2FA: true, redirectTo: '/verify-2fa', render: true, message: '' });
            }
            req.session.email = decryptedEmail;
            // return res.render('logado', { email: decryptedEmail });
            return res.json({ email: decryptedEmail, success: true, requires2FA: false, redirectTo: '/logado', message: ''});
        }
    }
    // return res.render('tindex', { erro: 'E-mail ou senha incorretos', query: {} });
    return res.json({ success: false, requires2FA: false, redirectTo: 'index', render: true, message: 'E-mail ou senha incorretos', query: {} });

    } catch (err) {
        console.error('Erro no login:', err.message);
        return res.status(500).send('Erro no servidor durante o login.');
    }
});


// Rota registro GET
app.get('/register', (req, res) => {
    res.render('public/register');
});


// Rota de Registro com Criptografia
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({message:'Preencha o e-mail e a senha'});
  console.log(email, password);
  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.status(400).json({ message: 'Formato de e-mail inválido'});

  try {
    const response = await axios.get('http://apilayer.net/api/check', {
      params: { access_key: CONFIG.MAILBOX_API_KEY, email, smtp: 1, format: 1 }
    });
    if (!response.data.format_valid || !response.data.mx_found || response.data.disposable) {
      return res.status(400).json({ message: 'Este endereço de e-mail não é válido ou não é permitido.'});
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const encryptedEmail = encrypt(email);
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');

    await dataBase.execute(
      'INSERT INTO users (email, password, email_hash) VALUES (?, ?, ?)',
      [encryptedEmail, hashedPassword, emailHash]
    );

    await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');
    return res.json({ message: '/?cadastro=sucesso' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Este e-mail já está cadastrado'});
    }
    console.error('Erro ao cadastrar:', err.message);
    return res.status(500).json({ message: 'Erro ao cadastrar usuário'});
  }
});


// Rota de Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Não foi possível fazer logout.');
    res.redirect('/sign-in');
  });
});


// Rotas de 2FA
app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/');
  res.render('verify-2fa', { erro: null });
});

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
    return res.render('logado', { email: req.session.email });
  } else {
    return res.render('verify-2fa', { erro: 'Código incorreto. Tente novamente.' });
  }
});


// Rota para ativar 2FA
app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  try {
    const emailHash = crypto.createHash('sha256').update(req.session.email).digest('hex');
    await dataBase.execute('UPDATE users SET two_factor_enabled = 1 WHERE email_hash = ?', [emailHash]);
    res.render('enable-2fa', { mensagem: '2FA ativado com sucesso.' });
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).send('Erro ao ativar 2FA');
  }
});


// --- NOVAS ROTAS PARA REDEFINIÇÃO DE SENHA ---

// ROTA GET: Exibe o formulário para solicitar a redefinição
app.get('/forgot', (req, res) => {
    // Agora enviamos 'erro' e 'sucesso', que é o que o template espera.
    res.render('forgot', { erro: null, sucesso: null });
});

// ROTA POST: Lida com a solicitação de redefinição
app.post('/forgot', async (req, res) => {
    const { email } = req.body;
    console.log('\n--- NOVA SOLICITAÇÃO EM /forgot ---');
    console.log(`1. E-mail recebido: ${email}`);

    try {
        const emailHash = crypto.createHash('sha256').update(email).digest('hex');
        const [rows] = await dataBase.execute('SELECT id FROM users WHERE email_hash = ?', [emailHash]);

        if (rows.length === 0) {
            console.log('2. Utilizador não encontrado.');
            return res.render('forgot', {
                erro: null,
                sucesso: 'Se um utilizador com este e-mail existir, um link de redefinição foi enviado.'
            });
        }

        const user = rows[0];
        console.log(`2. Utilizador encontrado! ID: ${user.id}`);

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

        // 🧪 Logs para depuração
        console.log('TOKEN GERADO:', token);
        console.log('EXPIRA EM:', expires);
        console.log('ID DO USUÁRIO:', user.id);

        await dataBase.execute(
            'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
            [token, expires, user.id]
        );
        console.log('3. Comando UPDATE executado.');

        const resetLink = `http://${req.headers.host}/reset/${token}`;
        await enviarEmail(
            email,
            'Redefinição de Senha',
            `Você solicitou uma redefinição de senha. Clique no link a seguir: ${resetLink}`
        );
        console.log('4. E-mail enviado.');

        res.render('forgot', {
            erro: null,
            sucesso: 'Se um utilizador com este e-mail existir, um link de redefinição foi enviado.'
        });

    } catch (err) {
        console.error('!!! ERRO CRÍTICO EM /forgot !!!');
        console.error(err);
        res.render('forgot', {
            sucesso: null,
            erro: 'Ocorreu um erro interno. Tente novamente.'
        });
    }
});


// ROTA GET: Exibe o formulário para criar a nova senha
app.get('/reset/:token', async (req, res) => {
    const { token } = req.params;
    console.log('\n--- NOVA SOLICITAÇÃO EM /reset/:token ---');
    console.log(`1. Token recebido da URL: ${token}`);

    try {
        // CORREÇÃO: Usamos UTC_TIMESTAMP() em vez de NOW() para garantir que a comparação
        // de fusos horários seja sempre correta, não importa onde o banco de dados esteja.
        const sqlQuery = 'SELECT id, email FROM users WHERE reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()';
        
        console.log('2. A procurar o utilizador no banco de dados com este token...');
        console.log(`3. A executar a seguinte consulta SQL: ${sqlQuery}`);

        const [rows] = await dataBase.execute(sqlQuery, [token]);

        if (rows.length === 0) {
            console.log('4. RESULTADO: Nenhum utilizador encontrado. A consulta com UTC_TIMESTAMP() também falhou ou o token é inválido.');
            return res.status(400).send('O link de redefinição de senha é inválido ou expirou.');
        }
        
        const user = rows[0];
        console.log(`4. RESULTADO: SUCESSO! Token válido encontrado para o utilizador ID: ${user.id}`);
        res.render('reset', { erro: null, token });

    } catch (err) {
        console.error('!!! ERRO CRÍTICO na rota GET /reset/:token !!!');
        console.error(err);
        res.status(500).send('Ocorreu um erro interno.');
    }
});


// ROTA POST: Salva a nova senha
app.post('/reset/:token', async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    try {
        // Repete a verificação do token para garantir a segurança
        const [rows] = await dataBase.execute(
            'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
            [token]
        );

        if (rows.length === 0) {
            return res.status(400).send('O link de redefinição de senha é inválido ou expirou.');
        }

        // Verifica se as senhas coincidem
       // if (password !== confirmPassword) {
       //     return res.render('reset', { erro: 'As senhas não coincidem.', token });
       // }

        // Gera o hash da nova senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Atualiza a senha e limpa o token para que não possa ser usado novamente
        await dataBase.execute(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = ?',
            [hashedPassword, token]
        );

        // Redireciona para a página de login com uma mensagem de sucesso
        res.redirect('/?redefinicao=sucesso'); // Você pode adicionar uma mensagem na página de login para isso

    } catch (err) {
        console.error('Erro em /reset/:token POST:', err.message);
        res.status(500).send('Ocorreu um erro ao redefinir a senha.');
    }
});
/*
*
*
*
*
*
*
*
*/

app.use((request, response, next) => {
    response.status(404).sendFile(path.join(__dirname, 'public', '/not-found.html'))
})

// 7. INICIAR O SERVIDOR
// ==========================================
app.listen({
    host: '0.0.0.0',
    // port: 3333
    port: process.env.PORT
}, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});