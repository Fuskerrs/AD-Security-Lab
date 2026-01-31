# Commandes Curl API - ETC Collector

## 📋 Configuration

**Token JWT:** (expire 2026-03-01)
```bash
export TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkYmQ5ZDUxMi0yN2ZiLTRlMTctODhkZS1lMTU2ZTA2NmJkODAiLCJpc3MiOiJldGMtY29sbGVjdG9yIiwic3ViIjoic3lzdGVtIiwiaWF0IjoxNzY5Nzk0Mjg4LCJleHAiOjE3NzIzODYyODgsInNlcnZpY2UiOiJldGMtY29sbGVjdG9yIiwibWF4VXNlcyI6MH0.ewLpPYbh9z9aLGA6mLzxE59FFKdBZFAaOYxbQeCbQkdTMRQzkwFdUCX18KBOntsBgBx_qbQkwROA0DNOpJi3n9Avg8AfhA8Mx6NAf7VWcxXEePN-8Gzp-WJKCfMC5DufrO7jLws1QP1wMAWJUcQa7-XaQmeLpSkLKyh6E9HqmWulaerktZ2jrv5IdR8Hzuhsamp8U03YU_gNJawgQIePQJlEyC-VKMWSwePTioJ1KvQAFhBnb7wANGtEQ6O1qrbYOAGfqpatQR8xGUz5Tvj3jA_VZV8VyYrWvT9EHLIca7nl2JMO1ggKrrUnNbAm9inNqgGszZiHDAWtoUIYeGqUdQ"
export API_URL="http://10.10.0.37:8443"
```

---

## 🔍 Endpoints disponibles

### 1. Health Check (sans auth)

```bash
curl -s $API_URL/health
```

### 2. Providers Info (sans auth)

```bash
curl -s $API_URL/api/v1/providers/info
```

### 3. Token Info

```bash
curl -s $API_URL/api/v1/auth/token/info \
    -H "Authorization: Bearer $TOKEN"
```

### 4. Test connexion AD

```bash
curl -s $API_URL/api/v1/audit/ad/status \
    -H "Authorization: Bearer $TOKEN"
```

### 5. Audit AD Synchrone

```bash
curl -s -X POST $API_URL/api/v1/audit/ad \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}'
```

**Sauvegarder le résultat:**
```bash
curl -s -X POST $API_URL/api/v1/audit/ad \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}' > audit-result.json
```

### 6. Audit AD Asynchrone

```bash
curl -s -X POST "$API_URL/api/v1/audit/ad?async=true" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}'
```

### 7. Liste des jobs

```bash
curl -s $API_URL/api/v1/audit/jobs \
    -H "Authorization: Bearer $TOKEN"
```

### 8. Statut d'un job

```bash
# Remplacer JOB_ID par l'ID retourné
curl -s $API_URL/api/v1/audit/jobs/JOB_ID \
    -H "Authorization: Bearer $TOKEN"
```

---

## 📊 Workflow complet - Mode Async

```bash
# 1. Lancer l'audit
RESPONSE=$(curl -s -X POST "$API_URL/api/v1/audit/ad?async=true" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}')

# 2. Extraire le Job ID
JOB_ID=$(echo $RESPONSE | grep -o '"job_id":"[^"]*' | cut -d'"' -f4)
echo "Job ID: $JOB_ID"

# 3. Vérifier le statut
curl -s $API_URL/api/v1/audit/jobs/$JOB_ID \
    -H "Authorization: Bearer $TOKEN"

# 4. Attendre et récupérer le résultat final
sleep 30
curl -s $API_URL/api/v1/audit/jobs/$JOB_ID \
    -H "Authorization: Bearer $TOKEN" > audit-result.json
```

---

## 🎯 Exemples rapides

**Test complet de l'API:**
```bash
echo "=== HEALTH ===" && \
curl -s $API_URL/health && echo -e "\n" && \
echo "=== PROVIDERS ===" && \
curl -s $API_URL/api/v1/providers/info && echo -e "\n" && \
echo "=== AD STATUS ===" && \
curl -s $API_URL/api/v1/audit/ad/status -H "Authorization: Bearer $TOKEN"
```

**Audit rapide (sync):**
```bash
curl -s -X POST $API_URL/api/v1/audit/ad \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}' | python3 -m json.tool
```

---

## ⚙️ Configuration détectée

- **Serveur AD:** ldaps://10.10.0.83:636
- **Domaine:** aza-me.cc
- **Base DN:** DC=aza-me,DC=cc
- **Service Account:** n8n Service
- **API Version:** 1.1.0

---

**Dernière mise à jour:** 2026-01-30
