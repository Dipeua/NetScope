# NetScope — Network Analyzer

Un analyseur réseau web, écrit en **Python** avec **zéro dépendance** (bibliothèque
standard uniquement). Entrez un domaine ou une IP, choisissez un outil, voyez le
résultat — avec **géolocalisation des sauts** du traceroute sur une carte mondiale.

## Fonctions

| Outil | Description |
|-------|-------------|
| 📡 **Ping** | Latence moyenne + perte de paquets |
| 🗺️ **Traceroute** | Liste des sauts + pays/ville/FAI + carte interactive |
| 🔌 **Ports** | Scan des ports courants (ouvert/fermé) |
| 📜 **Whois** | Registrar, dates, organisation, serveurs DNS |
| 🌐 **DNS** | Enregistrements A, AAAA, MX, NS, TXT, CNAME, SOA |

## Lancer

```bash
python3 app.py
```

Puis ouvrez **http://127.0.0.1:8000** dans le navigateur.

## Prérequis système

Les commandes suivantes doivent être disponibles (déjà présentes sur la plupart
des Linux/macOS) : `ping`, `traceroute`, `whois`, `dig`.

Sur Debian/Ubuntu/WSL si besoin :
```bash
sudo apt install iputils-ping traceroute whois dnsutils
```

## Notes

- La géolocalisation utilise l'API gratuite **ip-api.com** (HTTP, sans clé,
  ~15 requêtes/min). Une connexion Internet est requise pour la carte.
- Le serveur écoute sur `127.0.0.1` (local) uniquement. Pour l'exposer sur le
  réseau, changez `HOST = "0.0.0.0"` dans `app.py`.
- Multiplateforme : fonctionne dans n'importe quel navigateur, sur Windows,
  macOS et Linux.
