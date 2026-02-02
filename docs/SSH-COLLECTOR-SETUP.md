# SSH Configuration - Collector Server

**Date:** 2026-02-01
**Server:** dock-01 (10.10.0.37)
**User:** root
**OS:** Rocky Linux 9.6

---

## 🔑 SSH Key Authentication

### Clé générée
```
~/.ssh/id_collector (ed25519)
~/.ssh/id_collector.pub
```

### Config SSH (~/.ssh/config)
```
Host collector
    HostName 10.10.0.37
    User root
    IdentityFile ~/.ssh/id_collector
    StrictHostKeyChecking no
```

---

## 🚀 Utilisation

### Connexion simple
```bash
ssh collector
```

### Exécuter une commande
```bash
ssh collector "hostname && date"
```

### Copier un fichier VERS le serveur
```bash
scp localfile.txt collector:/tmp/
```

### Copier un fichier DEPUIS le serveur
```bash
scp collector:/tmp/remotefile.txt ./
```

---

## 🔧 Configuration AD

**Domain Controller:** 10.10.0.83 (DC-01.aza-me.cc)
**Domain:** aza-me.cc
**Credentials:** AZA-ME\\Administrator / 0Poseidon

---

## 📁 SMB Access Test

### Lister les shares
```bash
ssh collector 'smbclient -L //10.10.0.83 -U "AZA-ME\\Administrator" --password="0Poseidon"'
```

### Accéder au SYSVOL
```bash
ssh collector 'smbclient //10.10.0.83/SYSVOL -U "AZA-ME\\Administrator" --password="0Poseidon" -c "ls"'
```

### Télécharger un fichier GPO
```bash
ssh collector 'smbclient //10.10.0.83/SYSVOL -U "AZA-ME\\Administrator" --password="0Poseidon" -c "cd \"aza-me.cc/Policies/{GUID}/MACHINE/Microsoft/Windows NT/SecEdit\"; get GptTmpl.inf /tmp/GptTmpl.inf"'
```

---

## 🐳 Collecteur ETC

### Localisation service
```bash
ssh collector "docker ps | grep etc"
```

### Logs collecteur
```bash
ssh collector "docker logs -f <container_id>"
```

### Relancer l'audit
```bash
curl -X POST "http://10.10.0.37:8443/api/v1/audit/ad" \
    -H "Authorization: Bearer <TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"includeDetails": true}'
```

---

## 📝 Notes

- ✅ SMB fonctionne (port 445 accessible)
- ✅ SYSVOL accessible
- ✅ Fichiers GPO téléchargeables
- ⚠️ Problème avec lib @marsaud/smb2 dans le collecteur (timeout)

**Problème identifié:**
La bibliothèque Node.js @marsaud/smb2 utilisée par le collecteur a des timeouts, mais smbclient Linux natif fonctionne parfaitement.

**Solution:** Utiliser alternative SMB ou PowerShell remoting pour les checks registry.

---

**Créé par:** Claude Sonnet 4.5
**Dernière mise à jour:** 2026-02-01
