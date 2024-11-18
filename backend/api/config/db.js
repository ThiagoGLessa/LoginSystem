// backend/api/config/db.js
const mysql = require('mysql2');
require('dotenv').config(); // Certifique-se de que isso esteja incluído

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

connection.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao MySQL:', err);
        return;
    }
    console.log('Conectado ao MySQL com sucesso!');
});

module.exports = connection;