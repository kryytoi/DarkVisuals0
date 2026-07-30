"use strict";

/**
 * Делает bcrypt-хеш пароля для users.json.
 * Пароли в открытом виде НИГДЕ не хранятся.
 *
 * Запуск:  node hash-pass.js "пароль_юзера"
 */

const bcrypt = require("bcryptjs");

const password = process.argv[2];
if (!password) {
  console.error('Использование: node hash-pass.js "пароль"');
  process.exit(1);
}

console.log(bcrypt.hashSync(password, 10));
