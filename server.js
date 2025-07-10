// import express from 'express'
// import path from 'path'
// import { fileURLToPath } from 'url'

import express from 'express'

import dotenv from 'dotenv'
dotenv.config(); // Carrega as variáveis de ambiente do arquivo .env
import mysql from 'mysql2'
import bodyParser from 'body-parser'
import bcrypt from 'bcrypt'
import session from 'express-session'
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'

import path from 'path'
import {fileURLToPath} from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express();

app.use(express.static(path.join(__dirname, 'public')))

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
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Conectar ao banco de dados
db.connect((err) => {
  if (err) {
    console.error('!!!!!!!!!! ERRO AO CONECTAR AO BANCO DE DADOS !!!!!!!!!!');
    throw err;
  }
  console.log('Conectado ao banco de dados MySQL no AWS RDS!');
});


// 3. MIDDLEWARE
// ==========================================
// Configurar o body-parser para lidar com dados de formulário
app.use(bodyParser.urlencoded({ extended: true }));

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


// 4. ROTAS PÚBLICAS (Login, Registro, Páginas Iniciais)
// =======================================================

// Rota para servir a página de login/registro
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Rota para o registro de novos usuários
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email e senha são obrigatórios.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';

        db.query(sql, [email, hashedPassword], (err, result) => {
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

// Rota para o processo de login (LÓGICA CORRIGIDA)
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email e senha são obrigatórios.');
    }

    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], async (err, results) => {
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
            res.redirect('/enter-2fa-token');
        } else {
            req.session.userId = user.id;
            req.session.userEmail = user.email;
            res.redirect('/dashboard');
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
        res.redirect('/');
    });
});

// 5. ROTAS DE AUTENTICAÇÃO DE DOIS FATORES (2FA)
// =================================================

// Página que pede o token 2FA
app.get('/enter-2fa-token', (req, res) => {
    if (!req.session.pending_2fa_userId) {
        return res.redirect('/');
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
    db.query(sql, [userId], (err, results) => {
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
        db.query(sql, [secret, req.session.userId], (err, result) => {
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
    db.query(getUserSql, [userId], async (err, results) => { // o 'async' aqui é o importante
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
            db.query(disable2FASql, [userId], (disableErr, disableResult) => {
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

app.use((request, response, next) => {
    response.status(404).sendFile(path.join(__dirname, 'public', '/not-found.html'))
})

// 7. INICIAR O SERVIDOR
// ==========================================
app.listen({
    host: '0.0.0.0',
    port: process.env.PORT
})