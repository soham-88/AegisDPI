#!/usr/bin/env node
const bcrypt = require('bcryptjs');

const password = process.argv[2];
if (!password) {
    console.error('Usage: node hash-password.js <password>');
    process.exit(1);
}

const saltRounds = 10;
const hash = bcrypt.hashSync(password, saltRounds);
console.log(hash);
