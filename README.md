# Kemia Chat — Retbaa OS

Interface de chat web pour **Kemia Railway**, Chief of Staff IA de Retbaa.

🔗 **Live :** https://kemia.retbaa.com
📦 **Repo :** https://github.com/retbaa-dev/kemia-chat

---

## Stack

- **Backend :** Node.js + Express + WebSocket
- **Frontend :** HTML/CSS vanilla (design Retbaa OS)
- **LLM :** Anthropic Claude (avec fallback DeepSeek)
- **Hosting :** VM Hetzner (CPX22) → Caddy reverse proxy → PM2

## Architecture

```
kemia-chat/
├── server.js          # Serveur Express + WebSocket + endpoints API
├── public/
│   └── index.html     # Frontend SPA (sidebar, chat, logs, state)
├── ecosystem.config.js # PM2 ecosystem (env vars)
├── logs/              # Logs applicatifs (auto-rotation)
└── README.md
```

## Sécurité

- **Mot de passe** : via `CHATPASSWORD` en variable d'environnement (SHA-256 hash, pas en clair)
- **Rate limiting** : 30 req/min par IP (login) + 30 msg/min par session (chat)
- **Expiration session** : 24h avec purge automatique chaque heure
- **Headers** : CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Commandes** : blacklist de commandes dangereuses sur le endpoint `/api/exec`

## API Endpoints

| Endpoint | Méthode | Auth | Description |
|----------|---------|------|-------------|
| `/api/login` | POST | Rate-limited | Authentification (password → token) |
| `/api/state` | GET | Bearer token | État technique Retbaa OS |
| `/api/exec` | POST | Bearer token | Exécution commande (sandboxée) |
| `/api/logs` | GET | Bearer token | Logs système (dernières lignes) |
| `/api/health` | GET | Public | Healthcheck |
| WebSocket | `ws://` | Auth msg | Chat temps réel |

## Développement

```bash
# Installer les dépendances
npm install

# Variables d'environnement
export CHATPASSWORD="mot-de-passe-securise"
export DEEPSEEK_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export KEMIA_STATE_URL="https://nmmxamnm.gensparkclaw.com/kemia-state"

# Lancer en dev
node server.js

# Lancer avec PM2
pm2 start ecosystem.config.js --update-env
```

## Déploiement

Le service tourne sur la VM Hetzner `kemia-railway` (195.201.139.93) via PM2.

```bash
# Redéploiement
scp server.js root@195.201.139.93:/root/kemia-chat/
scp public/index.html root@195.201.139.93:/root/kemia-chat/public/
ssh root@195.201.139.93 "pm2 restart kemia-chat --update-env && pm2 save"
```

---

*Fait avec 🌿 par Kemia pour Retbaa OS*
