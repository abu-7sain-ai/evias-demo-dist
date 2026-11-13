#!/usr/bin/env node
// E-VIAS demo package — decrypt + unzip (Node built-ins only; Windows and macOS). No secrets in this file.
// Usage (in the folder that holds evias-coop-demo.enc):
//   the passcode comes ONLY from the environment variable EVIAS_PASSCODE (never a command-line argument, never written anywhere)
//   node unpack.mjs
// Wrong passcode → «رمز غير صحيح» / "Wrong passcode", exit code 2, and nothing is written.
// Cut-short or damaged download (size or SHA-256 differ from the published package) → «الملف ناقص، أعد التنزيل» /
// "download incomplete — download it again", exit code 3, checked BEFORE decrypting.
import { createDecipheriv, createHash, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { inflateRawSync } from "node:zlib";

const MAGIC = Buffer.from("EVIASPKG");
const here = process.cwd();
const encFile = resolve(here, process.argv[2] ?? "evias-coop-demo.enc");
const say = (ar, en) => console.log(`${ar}\n${en}`);
const EXPECT = { size: 6102212, sha256: "5a712b1f899b1b932f9273740dde036b366c10dca570fd713897dcffe2a67cd2" }; // filled in by scripts/package.mjs
const incomplete = (why) => { say("الملف ناقص، أعد التنزيل", `download incomplete — download evias-coop-demo.enc again (${why})`); process.exit(3); };
process.on("uncaughtException", (e) => { say("صار خطأ أثناء فك الحزمة. أعد التنزيل وجرّب مرة ثانية.", `Unpack failed: ${e && e.message ? e.message : e}. Download the package again and retry.`); process.exit(1); });

if (!existsSync(encFile)) { say("ما لقيت ملف evias-coop-demo.enc في هذا المجلد.", "evias-coop-demo.enc was not found in this folder."); process.exit(1); }
const pass = String(process.env.EVIAS_PASSCODE ?? "").trim().toUpperCase();
if (!pass) { say("رمز الدخول ناقص: يُمرَّر عبر المتغير EVIAS_PASSCODE.", "Passcode missing: pass it in the EVIAS_PASSCODE environment variable."); process.exit(1); }

const buf = readFileSync(encFile);
// size + hash first: the published unpack.mjs carries them; a VERSION.txt next to the file is used when present
let want = EXPECT;
const vfile = join(dirname(encFile), "VERSION.txt");
if (existsSync(vfile)) { const v = readFileSync(vfile, "utf8"); const s = v.match(/^size (\d+)$/m), h = v.match(/^sha256 ([0-9a-f]{64})$/m); if (s && h) want = { size: Number(s[1]), sha256: h[1] }; }
if (want) {
  if (buf.length !== want.size) incomplete(`${buf.length} of ${want.size} bytes`);
  if (createHash("sha256").update(buf).digest("hex") !== want.sha256) incomplete("checksum differs");
}
if (buf.length < 8 + 1 + 16 + 12 + 16 || !buf.subarray(0, 8).equals(MAGIC) || buf[8] !== 1) { say("الملف تالف أو ليس حزمة الديمو.", "The file is damaged or not the demo package."); process.exit(1); }
const salt = buf.subarray(9, 25), nonce = buf.subarray(25, 37), tag = buf.subarray(buf.length - 16), body = buf.subarray(37, buf.length - 16);
const key = scryptSync(pass, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
let zip;
try {
  const d = createDecipheriv("aes-256-gcm", key, nonce); d.setAuthTag(tag);
  zip = Buffer.concat([d.update(body), d.final()]);
} catch {
  say("رمز غير صحيح", "Wrong passcode"); process.exit(2);
}

// decrypted in memory only; now unzip into a hidden staging folder, then move into place
const stamp = Date.now();
const zipPath = join(tmpdir(), `evias-coop-demo-${stamp}.zip`);
writeFileSync(zipPath, zip);
const stage = join(here, `.evias-unpack-${stamp}`);
mkdirSync(stage, { recursive: true });

function jsUnzip(z, out) { // fallback when the OS tool is missing or fails
  let eocd = z.length - 22; while (eocd >= 0 && z.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("zip: no end record");
  const n = z.readUInt16LE(eocd + 10); let p = z.readUInt32LE(eocd + 16);
  for (let i = 0; i < n; i++) {
    const method = z.readUInt16LE(p + 10), csize = z.readUInt32LE(p + 20), nlen = z.readUInt16LE(p + 28), xlen = z.readUInt16LE(p + 30), clen = z.readUInt16LE(p + 32), off = z.readUInt32LE(p + 42);
    const name = z.subarray(p + 46, p + 46 + nlen).toString("utf8"); p += 46 + nlen + xlen + clen;
    const dst = resolve(out, name);
    if (!dst.startsWith(resolve(out) + sep)) throw new Error(`zip: unsafe path ${name}`);
    if (name.endsWith("/")) { mkdirSync(dst, { recursive: true }); continue; }
    const lo = off + 30 + z.readUInt16LE(off + 26) + z.readUInt16LE(off + 28);
    const raw = z.subarray(lo, lo + csize);
    mkdirSync(dirname(dst), { recursive: true });
    writeFileSync(dst, method === 8 ? inflateRawSync(raw) : raw);
  }
}

let ok = false;
if (process.platform === "win32") {
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `Expand-Archive -LiteralPath '${zipPath.replace(/'/g, "''")}' -DestinationPath '${stage.replace(/'/g, "''")}' -Force`], { stdio: "inherit" });
  ok = r.status === 0;
} else {
  const r = spawnSync("unzip", ["-q", "-o", zipPath, "-d", stage], { stdio: "inherit" });
  ok = r.status === 0;
}
if (!ok) jsUnzip(zip, stage);

const root = join(stage, "evias-coop-demo");
const src = existsSync(root) ? root : stage;
for (const name of readdirSync(src)) {
  const to = join(here, name);
  if (existsSync(to)) renameSync(to, join(here, `${name}.old-${stamp}`)); // never overwrite silently
  renameSync(join(src, name), to);
}
for (const d of [root, stage]) { try { rmdirSync(d); } catch { /* not empty or already gone */ } } // empty staging folders only
say("تم فك الحزمة. الخطوة التالية: npm install ثم npm run demo -- --lan", "Package unpacked. Next: npm install, then npm run demo -- --lan");
