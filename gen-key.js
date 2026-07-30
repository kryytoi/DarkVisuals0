"use strict";

/**
 * Генерирует новый AES-256 ключ + IV и печатает их в base64.
 * Эти значения:
 *   1. вставляешь в Render как AES_KEY_BASE64 и AES_IV_BASE64
 *   2. используешь при шифровании мода (npm run encrypt)
 *
 * Запуск:  node gen-key.js
 */

const crypto = require("crypto");

const key = crypto.randomBytes(32); // AES-256
const iv = crypto.randomBytes(16); // размер блока AES = 16 байт

console.log("AES_KEY_BASE64=" + key.toString("base64"));
console.log("AES_IV_BASE64=" + iv.toString("base64"));
