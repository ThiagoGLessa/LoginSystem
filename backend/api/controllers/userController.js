// backend/api/controllers/userController.js
const bcrypt = require('bcryptjs');
const User = require('../models/userModel');

exports.registerUser = (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ msg: 'Preencha todos os campos' });
    }

    User.findUserByEmail(email, async (err, result) => {
        if (result.length > 0) {
            return res.status(400).json({ msg: 'Email já cadastrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        User.createUser(name, email, hashedPassword, (err) => {
            if (err) return res.status(500).json({ msg: 'Erro ao registrar' });
            res.status(201).json({ msg: 'Usuário cadastrado com sucesso' });
        });
    });
};

exports.loginUser = (req, res) => {
    const { email, password } = req.body;

    User.findUserByEmail(email, async (err, result) => {
        if (result.length === 0) {
            return res.status(400).json({ msg: 'Email ou senha inválidos' });
        }

        const isMatch = await bcrypt.compare(password, result[0].password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Email ou senha inválidos' });
        }

        res.status(200).json({ msg: 'Login bem-sucedido' });
    });
};
