// mysql.js
const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'simai-db-instance.cdmwaesa0i63.sa-east-1.rds.amazonaws.com',
  user: 'admin',
  password: '*Juanpablo88', // cuidado com expor essa senha
  database: 'ar_condicionado',
  port: 3306
});

connection.connect((err) => {
  if (err) {
    console.error('Erro ao conectar no banco de dados:', err);
  } else {
    console.log('Conectado ao banco de dados com sucesso!');
  }
});

module.exports = connection;
