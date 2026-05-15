# 🛡️ SecureChat — Chat Sicura

Chat testuale sicura, auto-ospitata, accessibile da qualsiasi dispositivo e rete.

---

## ⚡ Avvio rapido (5 minuti)

### 1. Prerequisiti
- [Node.js](https://nodejs.org) v18 o superiore

### 2. Installa e avvia

```bash
cd securechat
npm install
node server.js
```

Apri il browser su: **http://localhost:3000**

### 3. Cambia la password (obbligatorio per uso reale!)

```bash
ROOM_PASSWORD=la_tua_password_sicura node server.js
```

Su Windows (PowerShell):
```powershell
$env:ROOM_PASSWORD="la_tua_password_sicura"; node server.js
```

---

## 🌐 Accesso da rete diversa (Internet)

### Opzione A — ngrok (più semplice, zero config)

1. Scarica [ngrok](https://ngrok.com) (gratuito)
2. Avvia il server: `node server.js`
3. In un secondo terminale: `ngrok http 3000`
4. Copia l'URL `https://xxxx.ngrok-free.app`
5. Condividilo con i tuoi contatti → usatelo come "Server" nel login

### Opzione B — Port forwarding sul router

1. Accedi al pannello del router (solitamente http://192.168.1.1)
2. Aggiungi una regola: **porta esterna 3000 → IP locale : 3000 (TCP)**
3. Trova il tuo IP pubblico su https://whatismyip.com
4. L'URL sarà: `http://TUO_IP_PUBBLICO:3000`

### Opzione C — VPS / server cloud (Hetzner, DigitalOcean, ecc.)

```bash
# Sul server remoto:
git clone / copia i file
npm install
ROOM_PASSWORD=password_segreta node server.js
```

Aggiungi un proxy Nginx con certificato SSL (Let's Encrypt) per HTTPS/WSS.

---

## 🔒 Sicurezza implementata

| Livello | Tecnologia | Cosa protegge |
|---------|-----------|---------------|
| **Autenticazione** | JWT HS256 (HMAC-SHA256) | Solo utenti autorizzati accedono |
| **Password** | HMAC-SHA256 con timing-safe compare | Brute force e timing attack |
| **Messaggi in transito** | AES-256-GCM (server-side) | Confidenzialità e integrità |
| **Sessioni** | Token con scadenza 2h | Sessioni persistenti non autorizzate |
| **Brute force** | Blocco IP dopo 5 tentativi falliti | Attacchi a dizionario |
| **Rate limiting** | Max 10 msg / 5 secondi per utente | Spam e flood |
| **Nessuna persistenza** | Messaggi solo in memoria RAM | Nessun log su disco |
| **XSS** | Escape HTML su tutti gli input | Iniezione di codice malevolo |
| **Header HTTP** | CSP, X-Frame-Options, ecc. | Attacchi via browser |
| **MAX clients** | 100 connessioni simultanee | DoS da connessioni eccessive |

### ⚠️ Cosa NON è incluso (e come aggiungerlo)

- **HTTPS/TLS**: In produzione aggiungi un certificato SSL (Let's Encrypt + Nginx). Senza HTTPS i messaggi sono in chiaro sul percorso di rete.
- **E2E crittografia client-client**: La crittografia attuale è server-side (il server vede il testo). Per vera E2E serve la Web Crypto API con scambio di chiavi (ECDH). Ottima aggiunta per v2.
- **2FA**: Per ambienti ad alto rischio, aggiungere TOTP (Google Authenticator).
- **Persistenza cifrata**: Se vuoi uno storico, usa SQLite con SQLCipher.

---

## ⚙️ Variabili d'ambiente

| Variabile | Default | Descrizione |
|-----------|---------|-------------|
| `PORT` | `3000` | Porta del server |
| `ROOM_PASSWORD` | `securechat2025` | **Cambia questo!** Password di accesso alla stanza |
| `JWT_SECRET` | (random) | Segreto JWT, generato automaticamente ad ogni riavvio |

Per sessioni persistenti dopo riavvio, imposta `JWT_SECRET` fisso:
```bash
JWT_SECRET=una_stringa_random_molto_lunga ROOM_PASSWORD=mia_pw node server.js
```

---

## 💬 Funzionalità

- ✅ Chat pubblica della stanza
- ✅ Messaggi privati (DM) tra utenti
- ✅ Indicatore di "sta scrivendo…"
- ✅ Lista utenti online in tempo reale
- ✅ Riconnessione automatica
- ✅ Notifiche DM non letti
- ✅ Sessione scaduta per inattività (2h)
- ✅ Interfaccia responsive mobile/desktop

---

## 🏗️ Struttura

```
securechat/
├── server.js      # Server Node.js (HTTP + WebSocket)
├── client.html    # Client web (servito dal server)
├── package.json   # Dipendenze
└── README.md      # Questa guida
```

---

## 📋 Dipendenze

- **ws** — libreria WebSocket per Node.js (l'unica dipendenza esterna)
- Tutto il resto usa moduli nativi Node.js: `crypto`, `http`, `fs`, `path`
