"use strict";

/**
 * Шифрует твой готовый мод (darkvisuals.jar) в darkvisuals.enc.
 * Использует ТОТ ЖЕ алгоритм, что и лаунчер расшифровывает:
 *   AES-256-CBC + PKCS7 padding   (в C#: Aes.Create() по умолчанию)
 *
 * Ключ и IV берутся из переменных окружения (те же, что стоят на Render):
 *   AES_KEY_BASE64, AES_IV_BASE64
 *
 * Запуск:
 *   AES_KEY_BASE64=... AES_IV_BASE64=... node encrypt-mod.js darkvisuals.jar darkvisuals.enc
 *
 * Потом заливаешь darkvisuals.enc в репозиторий notwhdwnwdwdjd.
 */

const fs = require("fs");
const crypto = require("crypto");

const inputPath = process.argv[2] || "darkvisuals.jar";
const outputPath = process.argv[3] || "darkvisuals.enc";

const keyB64 = process.env.AES_KEY_BASE64;
const ivB64 = process.env.AES_IV_BASE64;

if (!keyB64 || !ivB64) {
  console.error("Задай AES_KEY_BASE64 и AES_IV_BASE64 (см. gen-key.js).");
  process.exit(1);
}

const key = Buffer.from(keyB64, "base64");
const iv = Buffer.from(ivB64, "base64");

if (key.length !== 32) {
  console.error(`Ключ должен быть 32 байта (AES-256), а он ${key.length}.`);
  process.exit(1);
}
if (iv.length !== 16) {
  console.error(`IV должен быть 16 байт, а он ${iv.length}.`);
  process.exit(1);
}

const plain = fs.readFileSync(inputPath);

const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
cipher.setAutoPadding(true); // PKCS7 — как ждёт C#
const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

fs.writeFileSync(outputPath, encrypted);

console.log(`OK: ${inputPath} (${plain.length} b) -> ${outputPath} (${encrypted.length} b)`);
console.log("Теперь залей", outputPath, "в репозиторий notwhdwnwdwdjd.");
