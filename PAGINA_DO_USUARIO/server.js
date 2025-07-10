// server.js

// 1. Importar as bibliotecas
const express = require('express');
const mysql = require('mysql2/promise'); // Usamos a versão com Promises para async/await
const cors = require('cors');

// 2. Configurações Iniciais
const app = express();
const PORT = process.env.PORT || 3001; // Usa a porta do ambiente ou 3001 localmente

// Habilita o CORS para que seu front-end (HTML) possa fazer requisições
app.use(cors());

// NOVO E IMPORTANTE: Habilita o servidor a entender JSON no corpo das requisições.
// Essencial para a rota de controle.
app.use(express.json());

// Rota raiz para teste rápido se o backend está ativo
app.get('/', (req, res) => {
    res.send('API rodando com sucesso no Railway!');
});

// 3. Configurações do Banco de Dados
const dbConfig = {
    host: 'simai-db-instance.cdmwaesa0i63.sa-east-1.rds.amazonaws.com',
    user: 'admin',
    password: '*Juanpablo88', // Sua senha aqui
    database: 'ar_condicionado', // Nome do seu banco de dados
    port: 3306
};

// 4. Criação dos Endpoints (Rotas da API)

// Endpoint para buscar todas as marcas
app.get('/api/marcas', async (req, res) => {
    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log("Conectado ao DB para buscar marcas!");
        const [rows] = await connection.execute('SELECT id, nome FROM marcas ORDER BY nome ASC');
        res.json(rows);
    } catch (error) {
        console.error('Erro ao buscar marcas:', error);
        res.status(500).json({ error: 'Erro ao buscar dados das marcas.' });
    } finally {
        if (connection) await connection.end();
    }
});

// Endpoint para buscar os modelos de uma marca específica
app.get('/api/modelos', async (req, res) => {
    const marcaId = req.query.marca_id;
    if (!marcaId) {
        return res.status(400).json({ error: 'O ID da marca é obrigatório.' });
    }

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log(`Conectado ao DB para buscar modelos da marca ${marcaId}`);
        const [rows] = await connection.execute('SELECT id, nome FROM modelos WHERE marca_id = ? ORDER BY nome ASC', [marcaId]);
        res.json(rows);
    } catch (error) {
        console.error('Erro ao buscar modelos:', error);
        res.status(500).json({ error: 'Erro ao buscar dados dos modelos.' });
    } finally {
        if (connection) await connection.end();
    }
});

// NOVO ENDPOINT: Rota para receber os comandos do Controle Manual
app.post('/api/control', (req, res) => {
    // Extrai os dados enviados pelo front-end no corpo da requisição
    const { comando, marcaId, modeloId } = req.body;

    // Validação para garantir que todos os dados necessários foram recebidos
    if (!comando || !marcaId || !modeloId) {
        return res.status(400).json({ message: 'Erro: Informações incompletas. É necessário enviar comando, marcaId e modeloId.' });
    }

    // Log no console do servidor para vermos o que foi recebido
    console.log(`✅ Comando recebido: '${comando}' | Marca ID: ${marcaId} | Modelo ID: ${modeloId}`);

    // =======================================================================
    // AQUI ENTRA A LÓGICA DE HARDWARE
    // Neste ponto, você usaria uma biblioteca para interagir com o hardware
    // e enviar o sinal infravermelho (IR) correto com base nos dados recebidos.
    // Exemplo de como a lógica poderia ser:
    // const codigoIR = buscarCodigoNoBanco(marcaId, modeloId, comando);
    // enviarSinalIR(codigoIR);
    // =======================================================================

    // Simplesmente respondemos ao front-end com uma mensagem de sucesso
    res.status(200).json({ message: `Comando '${comando}' foi recebido e processado!` });
});

// 5. Iniciar o Servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}.`);
});
