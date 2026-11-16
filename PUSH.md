# push karo — 3 commands

Repo banane se pehle GitHub pe **public** repo banao (naam: `nmms-unpack`).
Private pe ARM runner free nahi hai — public zaroori hai.

```bash
cd "_gh"
git init -b main
git add .
git commit -m "nmms unpack: call nx_decrypt natively on ARM64 runner"
git remote add origin https://github.com/<YOUR_USER>/nmms-unpack.git
git push -u origin main
```

Push ke baad:
1. Repo → **Actions** tab
2. `nmms-unpack` → **Run workflow** → Run
3. ~2-3 min wait
4. Run khatam → neeche **Artifacts** → `nmms-decrypted` download

Andar milega:
- `out/classes*.dex`  ← asli app code
- `payload.bin`        ← raw decrypted payload
- `run.log`            ← har JNI call + cert hash

Ye dex mujhe de dena, main modder ka NMMS login popup nikal ke official login
bachaunga, phir rebuild + sign.
