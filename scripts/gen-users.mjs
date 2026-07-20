// 生成 data/users.json —— 预设 5 个用户，随机口令，只存哈希，明文仅在此打印一次。
// 用法：node scripts/gen-users.mjs [name1 name2 ...]
//   不带参数：生成 admin, user2, user3, user4, user5
//   带参数：用你给的名字（第一个为管理员，存量数据归给他）
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// 生成一串好念但够强的口令：4 组 4 位 base32（去掉易混字符）
function genPassword() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 去掉 I L O 0 1
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) out += '-';
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out; // 形如 K7QM-3XPT-9WFH-R2ND
}

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + ':' + password).digest('hex');
}

const names = process.argv.slice(2);
const finalNames = names.length ? names : ['admin', 'user2', 'user3', 'user4', 'user5'];

if (fs.existsSync(USERS_FILE)) {
  console.error('\n⚠  data/users.json 已存在。为避免覆盖现有用户和口令，脚本已中止。');
  console.error('   如果确实要重建，请先手动删除或改名该文件，再重新运行。\n');
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });

const users = [];
const plaintext = [];
finalNames.forEach((name, idx) => {
  const id = 'u_' + crypto.randomBytes(6).toString('hex');
  const salt = crypto.randomBytes(12).toString('hex');
  const password = genPassword();
  users.push({
    id,
    name,
    salt,
    hash: hashPassword(password, salt),
    role: idx === 0 ? 'admin' : 'member', // 第一个是管理员，存量无主数据归他
  });
  plaintext.push({ name, password });
});

fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

console.log('\n✅ 已生成 data/users.json（只含哈希，不含明文口令）\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  以下口令只显示这一次，请立刻复制并私下分发：');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
plaintext.forEach(({ name, password }, i) => {
  const tag = i === 0 ? ' (管理员)' : '';
  console.log(`  ${name}${tag}\n    口令：${password}\n`);
});
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  提示：口令无法找回，只能用脚本重置。妥善保存。\n');
