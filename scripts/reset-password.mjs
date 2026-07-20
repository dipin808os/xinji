// 重置某个用户的口令（也可用于新增用户后补口令）。
// 用法：node scripts/reset-password.mjs <name>
//   给已存在的用户生成新口令；若该 name 不存在则新增为普通成员。
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

function genPassword() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) out += '-';
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}
const hashPassword = (password, salt) =>
  crypto.createHash('sha256').update(salt + ':' + password).digest('hex');

const name = process.argv[2];
if (!name) {
  console.error('用法：node scripts/reset-password.mjs <name>');
  process.exit(1);
}
if (!fs.existsSync(USERS_FILE)) {
  console.error('data/users.json 不存在，请先运行 gen-users.mjs');
  process.exit(1);
}

const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
let user = users.find((u) => u.name === name);
const password = genPassword();
const salt = crypto.randomBytes(12).toString('hex');

if (user) {
  user.salt = salt;
  user.hash = hashPassword(password, salt);
  console.log(`\n✅ 已重置「${name}」的口令：`);
} else {
  user = {
    id: 'u_' + crypto.randomBytes(6).toString('hex'),
    name,
    salt,
    hash: hashPassword(password, salt),
    role: 'member',
  };
  users.push(user);
  console.log(`\n✅ 已新增用户「${name}」，口令：`);
}
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log(`\n    ${password}\n\n（只显示这一次，请立刻私下分发。）\n`);
