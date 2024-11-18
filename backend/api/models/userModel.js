// backend/api/models/userModel.js
const connection = require('../config/db');

const createUser = (name, email, password, callback) => {
    const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    connection.query(sql, [name, email.toLowerCase(), password], callback);
};

const findUserByEmail = (email, callback) => {
    const sql = 'SELECT * FROM users WHERE email = ?';
    connection.query(sql, [email.toLowerCase()], callback);
};

module.exports = { createUser, findUserByEmail };
