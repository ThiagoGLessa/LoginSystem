// backend/api/server.js
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao MySQL:', err);
    } else {
        console.log('Conectado ao MySQL com sucesso!');
    }
});

// Endpoint para registro de usuários
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    try {
        // Verificar se o email já existe
        const [user] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

        if (user.length > 0) {
            return res.status(409).json({ message: 'Email já cadastrado!' });
        }

        // Criptografar a senha
        const hashedPassword = await bcrypt.hash(password, 10);

        // Inserir novo usuário
        await db.promise().query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email.toLowerCase(), hashedPassword]);

        return res.status(201).json({ message: 'Usuário registrado com sucesso!' });
    } catch (error) {
        console.error('Erro ao registrar:', error);
        return res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Requisição de login recebida:', req.body);

    if (!email || !password) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios!' });
    }

    try {
        // Buscar o usuário pelo email (convertido para minúsculas)
        const [userResult] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

        // Verificar se o usuário existe
        if (userResult.length === 0) {
            return res.status(404).json({ message: 'Email ou senha inválidos' });
        }

        const user = userResult[0];

        // Comparar a senha inserida com a senha criptografada no banco de dados
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Email ou senha inválidos' });
        }

        // Login bem-sucedido
        return res.status(200).json({ success: true, message: 'Login bem-sucedido!' });

    } catch (error) {
        console.error('Erro ao logar:', error);
        return res.status(500).json({ message: 'Erro interno do servidor' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

// NOVA LINHA

const jwt = require('jsonwebtoken');
const secretKey = 'suaChaveSecreta'; // Defina uma chave secreta segura

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [user] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

        if (user.length === 0) {
            return res.status(401).json({ message: 'Email ou senha inválidos' });
        }

        const isPasswordMatch = await bcrypt.compare(password, user[0].password);

        if (!isPasswordMatch) {
            return res.status(401).json({ message: 'Email ou senha inválidos' });
        }

        // Gerar um token JWT
        const token = jwt.sign({ id: user[0].id }, secretKey, { expiresIn: '1h' });

        res.json({ success: true, token });
    } catch (error) {
        console.error('Erro ao logar:', error);
        res.status(500).json({ message: 'Erro ao logar' });
    }
});
