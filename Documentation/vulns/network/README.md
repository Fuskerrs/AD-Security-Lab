# Network (12 vulnérabilités)

**Sévérité :** 0 Critical, 4 High, 7 Medium, 1 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 215 | DNS_ZONE_TRANSFER_UNRESTRICTED | High | DNS Zone Transfer Unrestricted | ✅ | **1** | Confirmé (injecté TransferAnyServer) |
| 216 | DNS_DYNAMIC_UPDATE_INSECURE | High | DNS Dynamic Update Insecure | ✅ | **1** | Confirmé (injecté NonsecureAndSecure) |
| 217 | DC_TIME_SYNC_ISSUE | High | DC Time Synchronization Review | ✅ | **1** | Confirmé |
| 218 | SYSVOL_NETLOGON_PERMISSIONS | High | SYSVOL/NETLOGON Permissions Review | ❓ | - | Non vérifié |
| 219 | DC_BACKUP_OLD | Medium | Domain Controller Backup Review | ✅ | **1** | Confirmé |
| 220 | DC_DISK_SPACE_LOW | Medium | DC Disk Space Monitoring | ❌ | 0 | Non trouvé |
| 221 | DFSR_NOT_CONFIGURED | Medium | DFSR Migration Status | ❌ | 0 | Non trouvé (DFSR OK) |
| 222 | DNSSEC_NOT_ENABLED | Medium | DNSSEC Not Enabled | ❓ | - | Non vérifié |
| 223 | DNS_WILDCARD_RECORDS | Medium | DNS Wildcard Records Detected | ❓ | - | Non vérifié |
| 224 | NTP_NOT_CONFIGURED | Medium | NTP Configuration Review Needed | ✅ | **1** | Confirmé |
| 225 | SITE_TOPOLOGY_ISSUES | Medium | AD Site Topology Issues | ❌ | 0 | Non trouvé |
| 226 | SUBNET_MISSING | Low | AD Sites Missing Subnets | ✅ | **1** | Confirmé |

**Résumé : 6/12 confirmés (dont 2 injectés) | 3 non trouvés | 3 non vérifiés**

---

## Détail des vulnérabilités

### 215. DNS_ZONE_TRANSFER_UNRESTRICTED (High) — ✅ 1 instance
**Description :** Zone transfers allowed to any server. Attackers can enumerate DNS records and map internal topology.
**Résultat :** Zone primaire configurée avec `SecureSecondaries = TransferAnyServer` (injecté via Set-DnsServerPrimaryZone). N'importe quel serveur peut effectuer un transfert de zone complet.

---

### 216. DNS_DYNAMIC_UPDATE_INSECURE (High) — ✅ 1 instance
**Description :** Non-secure dynamic updates allowed. Attackers can inject malicious DNS records without auth.
**Résultat :** Zone configurée avec `DynamicUpdate = NonsecureAndSecure` (injecté). Les attaquants peuvent injecter des enregistrements DNS malveillants sans authentification.

---

### 217. DC_TIME_SYNC_ISSUE (High) — ✅ 1 instance
**Description :** DCs with potential time sync issues. Kerberos requires time difference < 5 minutes.
**Résultat :** Source de temps : **Local CMOS Clock**. Le DC utilise son horloge locale au lieu d'un serveur NTP externe. Risque de dérive temporelle affectant l'authentification Kerberos.

---

### 218. SYSVOL_NETLOGON_PERMISSIONS (High) — ❓ Non vérifié
**Description :** Weak permissions allow attackers to modify logon scripts and GPOs.
**Résultat :** Non testé individuellement.

---

### 219. DC_BACKUP_OLD (Medium) — ✅ 1 instance
**Description :** DCs should be backed up regularly. Tombstone lifetime is 180 days.
**Résultat :** Dernier backup il y a **92 jours**. Approche le seuil de tombstone lifetime (180 jours). Un backup récent est recommandé.

---

### 220. DC_DISK_SPACE_LOW (Medium) — ❌ 0 instance
**Description :** Low disk space can cause AD database corruption and replication failures.
**Résultat :** Tous les disques ont plus de 15% d'espace libre. Pas de problème d'espace disque.

---

### 221. DFSR_NOT_CONFIGURED (Medium) — ❌ 0 instance
**Description :** FRS is deprecated. SYSVOL should use DFSR.
**Résultat :** DFSR migration complétée (**Eliminated** state = phase 3). SYSVOL utilise bien DFSR.

---

### 222. DNSSEC_NOT_ENABLED (Medium) — ❓ Non vérifié
**Description :** DNS responses can be spoofed, enabling cache poisoning and MITM attacks.
**Résultat :** Non testé individuellement.

---

### 223. DNS_WILDCARD_RECORDS (Medium) — ❓ Non vérifié
**Description :** Wildcard DNS records (*.domain) can be exploited for MITM attacks.
**Résultat :** Non testé individuellement.

---

### 224. NTP_NOT_CONFIGURED (Medium) — ✅ 1 instance
**Description :** PDC Emulator must be configured as authoritative time source.
**Résultat :** Type : **NT5DS** (synchronisation locale). Le PDC Emulator devrait être configuré en mode NTP avec un serveur NTP externe fiable (ex: pool.ntp.org).

---

### 225. SITE_TOPOLOGY_ISSUES (Medium) — ❌ 0 instance
**Description :** Sites without DCs cause clients to authenticate remotely, increasing latency.
**Résultat :** Aucun site sans DC détecté. Topologie de sites correcte.

---

### 226. SUBNET_MISSING (Low) — ✅ 1 instance
**Description :** Sites without subnet definitions. Clients select DCs randomly.
**Résultat :** **Default-First-Site-Name** sans sous-réseau défini. Les clients de ce site ne peuvent pas identifier automatiquement le DC le plus proche.
