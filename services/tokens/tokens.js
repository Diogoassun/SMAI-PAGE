// server.js

// 1. IMPORTAÇÕES
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto'); // Módulo nativo do Node para gerar tokens seguros

// 2. SETUP INICIAL
const app = express();
app.use(express.json()); // Middleware para interpretar JSON
app.use(cookieParser()); // Middleware para interpretar cookies

const PORT = process.env.PORT || 3000;

// 3. BANCO DE DADOS EM MEMÓRIA (SIMULAÇÃO)
// Em uma aplicação real, estes dados estariam em um banco de dados como PostgreSQL ou MongoDB.
const users = [
    { id: 1, email: 'usuario@email.com', password: 'senha123', role: 'user' },
    { id: 2, email: 'admin@email.com', password: 'admin123', role: 'admin' },
];

// Armazenaremos os refresh tokens aqui. Em produção, use um banco de dados (ex: Redis ou uma tabela SQL).
// NUNCA armazene o token puro. Armazene um HASH dele. Para este exemplo, manteremos simples.
let refreshTokens = [];

// 4. FUNÇÕES AUXILIARES DE TOKEN
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' }); // Vida útil curta
}

// 5. MIDDLEWARE DE AUTENTICAÇÃO (O "GUARDA" DAS ROTAS)
function tcheckAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ message: 'Token de acesso não fornecido.' });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, userPayload) => {
        if (err) {
            // Se o erro for de expiração, o frontend saberá que precisa usar o refresh token.
            return res.status(403).json({ message: 'Token de acesso inválido ou expirado.' });
        }
        req.user = userPayload;
        next();
    });
}


// 6. ROTAS DA API

// ===================================
// ROTA DE LOGIN
// ===================================
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    // Valida o usuário (simulação)
    const user = users.find(u => u.email === email && u.password === password);

    if (!user) {
        return res.status(401).json({ message: 'Email ou senha inválidos.' });
    }

    // Prepara o payload para os tokens
    const userPayload = { id: user.id, role: user.role };

    const accessToken = generateAccessToken(userPayload);
    const refreshToken = crypto.randomBytes(40).toString('hex'); // Token seguro e aleatório

    // Salva o refresh token no nosso "banco de dados"
    refreshTokens.push({
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Expira em 7 dias
        status: 'active'
    });

    // Envia o refresh token em um cookie HttpOnly seguro
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use 'true' em produção (HTTPS)
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias em milissegundos
    });

    res.json({ accessToken });
});


// ===================================
// ROTA DE ATUALIZAÇÃO DE TOKEN (O CORAÇÃO DA ROTAÇÃO)
// ===================================
app.post('/api/refresh', (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token não fornecido.' });
    }

    // Encontra o token no nosso "banco de dados"
    const storedToken = refreshTokens.find(rt => rt.token === refreshToken);

    if (!storedToken) {
        return res.status(403).json({ message: 'Refresh token inválido.' });
    }
    
    // === PONTO CRUCIAL DE SEGURANÇA: DETECÇÃO DE ROUBO ===
    // Se o token encontrado já foi revogado, significa que alguém (talvez um invasor)
    // está tentando reutilizar um token antigo. Como medida de segurança, invalidamos
    // TODOS os refresh tokens daquele usuário.
    if (storedToken.status === 'revoked') {
        console.warn(`Tentativa de reutilização de refresh token revogado! UserID: ${storedToken.userId}`);
        // Revoga todos os tokens do usuário suspeito
        refreshTokens = refreshTokens.filter(rt => rt.userId !== storedToken.userId);
        return res.status(403).json({ message: 'Refresh token reutilizado. Sessão invalidada por segurança.' });
    }

    // Revoga o token que acabamos de usar
    storedToken.status = 'revoked';

    // Gera um novo par de tokens
    const userPayload = { id: storedToken.userId, role: users.find(u => u.id === storedToken.userId).role };
    const newAccessToken = generateAccessToken(userPayload);
    const newRefreshToken = crypto.randomBytes(40).toString('hex');

    // Salva o novo refresh token
    refreshTokens.push({
        token: newRefreshToken,
        userId: storedToken.userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        status: 'active'
    });

    // Envia o novo refresh token no cookie
    res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken: newAccessToken });
});


// ===================================
// ROTA DE LOGOUT
// ===================================
app.post('/api/logout', (req, res) => {
    const { refreshToken } = req.cookies;
    
    // Remove o token do "banco de dados"
    refreshTokens = refreshTokens.filter(rt => rt.token !== refreshToken);
    
    // Limpa o cookie do cliente
    res.clearCookie('refreshToken');
    
    res.status(200).json({ message: 'Logout realizado com sucesso.' });
});

// ===================================
// ROTA PROTEGIDA (EXEMPLO)
// ===================================
app.get('/api/profile', tcheckAuth, (req, res) => {
    // Graças ao middleware `checkAuth`, se chegamos aqui, o usuário está autenticado.
    // O payload do usuário está disponível em `req.user`.
    const user = users.find(u => u.id === req.user.id);
    res.json({
        message: `Bem-vindo à sua área protegida, ${user.email}!`,
        user: {
            id: user.id,
            email: user.email,
            role: user.role,
        }
    });
});


// 7. INICIAR O SERVIDOR
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT} às ${new Date().toLocaleTimeString('pt-BR')} em Quixadá, Ceará.`);
});