# DEFAIR — Roadmap projet

> **Nom de travail :** DEFAIR / DFIR Workbench  
> **Type :** plateforme DFIR conteneurisée, modulaire, automatisable et pilotable par MCP  
> **Objectif :** fournir un environnement forensic reproductible regroupant les principaux outils DFIR open source et spécialisés, avec une couche d’orchestration commune, une normalisation des résultats, une timeline unifiée, une CLI, une API et un serveur MCP.

---

## 0. Vision

### 0.1 Objectif général

Construire une « couteau suisse » de la forensic capable de :

- recevoir une ou plusieurs sources d’évidence ;
- identifier automatiquement leur nature et leur plateforme ;
- sélectionner les outils pertinents ;
- exécuter les analyses de manière reproductible ;
- stocker les résultats et leur provenance ;
- normaliser les artefacts dans un modèle commun ;
- construire des timelines et des vues de recherche ;
- corréler les événements et détections ;
- rechercher des IOC, patterns et TTP ;
- générer des exports et rapports ;
- exposer toutes ces capacités via CLI, API et MCP ;
- permettre à un analyste ou à un agent IA de piloter l’analyse sans accès direct au shell.

### 0.2 Principe directeur

Le projet ne doit pas être « un énorme container avec plein de binaires ».

Il doit être une **plateforme d’orchestration forensic** dont les outils externes constituent des moteurs spécialisés.

Architecture cible :

```text
                         Analyst / AI Agent
                                │
                    ┌───────────┴───────────┐
                    │                       │
                   CLI                     MCP
                    │                       │
                    └───────────┬───────────┘
                                │
                           API / Core
                                │
                        ┌───────▼────────┐
                        │  Orchestrator  │
                        └───────┬────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
        Evidence Manager   Tool Registry     Job Engine
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        │                       │                        │
      Windows                 Linux                   Network
        │                       │                        │
  EZ Tools / Dissect      Dissect / Plaso       Zeek / TShark / ...
  Hayabusa / Chainsaw     journal/log parsers   Suricata / PCAP
        │                       │                        │
        └───────────────────────┼────────────────────────┘
                                │
                      Normalization Layer
                                │
                 ┌──────────────┼───────────────┐
                 │              │               │
              Timeline       Findings          IOC
                 │              │               │
                 └──────────────┼───────────────┘
                                │
                         Reports / Export
```

### 0.3 Principes non négociables

1. **Read-only par défaut sur les evidence.**
2. **Hash et provenance systématiques.**
3. **Chaque exécution doit être traçable et reproductible.**
4. **Les outils externes ne doivent pas dicter l’architecture interne.**
5. **MCP ne doit jamais exposer un shell arbitraire.**
6. **Les résultats doivent être normalisés et reliés aux artefacts sources.**
7. **La couche forensic déterministe reste indépendante de l’IA.**
8. **Chaque outil doit être versionné et testable.**
9. **Un analyste doit pouvoir utiliser le projet sans MCP.**
10. **Le projet doit pouvoir fonctionner hors ligne pour un maximum de scénarios.**

---

# 1. Périmètre fonctionnel cible

## 1.1 Sources d’évidence

### Images disque

- RAW / DD
- E01 / Ex01
- VHD / VHDX
- VMDK
- QCOW2
- éventuellement AFF4
- archives de triage
- collections logiques

### Systèmes de fichiers

- NTFS
- FAT / exFAT
- ext2 / ext3 / ext4
- XFS
- APFS
- HFS+
- autres formats pris en charge par les moteurs retenus

### Mémoire

- raw memory dumps
- dumps issus d’outils de collecte
- support progressif des profils/OS modernes

### Logs / artefacts seuls

- EVTX
- journaux Linux
- Sysmon
- auditd
- Apache / Nginx
- PowerShell
- fichiers applicatifs
- SQLite
- CSV / JSON / JSONL
- PCAP

---

# 2. Périmètre des moteurs forensic

## 2.1 Bloc Eric Zimmerman / EZ Tools

Créer un **module EZ Tools** regroupant les outils pertinents et documentés de la suite, avec détection de version, wrapper d’exécution, normalisation et tests d’intégration.

### Axes prioritaires

- MFT / NTFS
- EVTX
- Registry
- Prefetch
- Amcache
- AppCompatCache / Shimcache
- LNK
- ShellBags
- Recycle Bin
- Scheduled Tasks / artefacts associés
- SQLite / bases applicatives
- Windows Search / artefacts similaires lorsque pertinents
- parsing / export de timelines
- utilitaires complémentaires de la suite

### Outils explicitement à étudier / intégrer

- `MFTECmd`
- `RECmd`
- `Registry Explorer` — selon faisabilité headless
- `EvtxECmd`
- `LECmd`
- `JLECmd`
- `PECmd`
- `AmcacheParser`
- `AppCompatCacheParser`
- `RBCmd`
- `SBECmd`
- `SQLECmd`
- `SDBExplorer` — selon faisabilité headless
- `ShellBagsExplorer` — selon faisabilité headless
- `WxTCmd`
- `bstrings`
- `TimelineExplorer` — traiter comme client GUI/export, pas comme dépendance serveur obligatoire
- autres EZ Tools pertinentes au moment de l’implémentation

> **Note :** les noms, versions, dépendances et modalités d’exécution de la suite EZ Tools devront être revalidés au moment de l’implémentation. Les outils GUI ne doivent pas être artificiellement forcés dans un environnement headless.

---

## 2.2 Dissect

Dissect doit constituer l’un des moteurs centraux pour :

- identification d’hôte ;
- découverte d’artefacts ;
- parsing de systèmes ;
- accès à des images et structures forensic ;
- extraction d’informations ;
- préparation des données pour d’autres moteurs.

Objectif : faire de Dissect le **pivot d’abstraction** lorsque cela a du sens, sans empêcher l’usage direct des outils spécialisés.

---

## 2.3 Hayabusa

Cas d’usage :

- parsing EVTX ;
- détection Sigma ;
- hunting Windows ;
- scoring / sévérité ;
- sortie CSV / JSON / JSONL ;
- corrélation des détections avec les événements de timeline.

À intégrer comme moteur de détection spécialisé, pas comme simple parseur de logs.

---

## 2.4 Plaso

Cas d’usage :

- supertimeline ;
- parsing de multiples sources temporelles ;
- normalisation de timestamps ;
- export vers des formats de travail ;
- alimentation du Timeline Engine interne.

Le système doit conserver la possibilité de distinguer :

- timestamp brut ;
- timestamp normalisé ;
- timezone ;
- précision ;
- type d’événement ;
- source ;
- artefact source.

---

## 2.5 Volatility 3

Cas d’usage :

- processus ;
- réseau ;
- DLL / modules ;
- handles ;
- services ;
- persistance ;
- autres plugins pertinents.

Intégration progressive avec un modèle de résultat commun.

---

## 2.6 Chainsaw

À étudier pour compléter :

- recherche rapide dans les EVTX ;
- détection Sigma ;
- workflows de threat hunting ;
- comparaison avec Hayabusa.

Décider si l’outil est complémentaire ou redondant selon les cas d’usage réellement couverts.

---

## 2.7 The Sleuth Kit / libewf / dfVFS / autres bibliothèques

Étudier les bibliothèques comme briques bas niveau plutôt que comme outils utilisateur.

Objectif : permettre :

- ouverture d’images ;
- accès aux partitions ;
- extraction ;
- métadonnées ;
- carving ;
- intégration avec l’orchestrateur.

---

## 2.8 Network / PCAP

À intégrer après le cœur Windows :

- TShark
- Zeek
- Suricata
- outils PCAP complémentaires selon les besoins

Cas d’usage :

- connexions réseau ;
- DNS ;
- HTTP ;
- TLS metadata ;
- beaconing ;
- exfiltration ;
- corrélation host/network.

---

## 2.9 Linux DFIR

Prévoir au minimum :

- journald / systemd ;
- auth logs ;
- SSH ;
- shell history ;
- cron ;
- systemd services ;
- users / groups ;
- sudo ;
- packages ;
- web server logs ;
- persistence ;
- network state ;
- fichiers récents / supprimés ;
- traces de conteneurs / Docker lorsque présents.

---

## 2.10 Mobile / macOS / autres plateformes

Phase ultérieure.

Le framework doit toutefois être conçu pour ne pas être limité structurellement à Windows.

---

# 3. Architecture logicielle

## 3.1 Core

Créer un package central avec :

```text
core/
├── cases/
├── evidence/
├── artifacts/
├── jobs/
├── findings/
├── timeline/
├── provenance/
├── ioc/
├── schemas/
└── configuration/
```

Responsabilités :

- modèles métier ;
- validation ;
- gestion des identifiants ;
- état des jobs ;
- provenance ;
- politiques de sécurité ;
- règles d’orchestration.

---

# 4. Modèle de données

## 4.1 Case

```json
{
  "id": "CASE-2026-001",
  "name": "Incident host 01",
  "description": "",
  "created_at": "...",
  "status": "active"
}
```

## 4.2 Evidence

```json
{
  "id": "EVD-001",
  "case_id": "CASE-2026-001",
  "type": "disk_image",
  "path": "/evidence/host01.E01",
  "size": 123456,
  "sha256": "...",
  "read_only": true,
  "source": "host01"
}
```

## 4.3 ToolRun

Chaque exécution conserve :

- outil ;
- version ;
- commande normalisée ;
- paramètres ;
- evidence d’entrée ;
- fichiers de sortie ;
- exit code ;
- stdout/stderr ;
- hash des outputs ;
- durée ;
- worker ;
- timestamp ;
- statut.

## 4.4 Artifact

```json
{
  "id": "ART-001",
  "case_id": "CASE-2026-001",
  "artifact_type": "windows.evtx.process_creation",
  "source_tool": "EvtxECmd",
  "source_run": "RUN-001",
  "source_file": "Security.evtx",
  "source_offset": null,
  "timestamp": "..."
}
```

## 4.5 Finding

```json
{
  "id": "F-001",
  "severity": "high",
  "title": "Suspicious PowerShell execution",
  "description": "...",
  "confidence": 0.92,
  "evidence_refs": ["ART-001", "ART-019"],
  "detection_refs": ["sigma:..."],
  "timeline_refs": ["TL-883"]
}
```

---

# 5. Provenance et chaîne de confiance

## 5.1 Exigence

Tout résultat doit permettre de répondre à :

> « De quelle evidence et de quel traitement cette information provient-elle ? »

Chaîne cible :

```text
Evidence
  ↓
Hash
  ↓
ToolRun
  ↓
Raw Output
  ↓
Parser / Normalizer
  ↓
Normalized Artifact
  ↓
Timeline / Finding
  ↓
Report
```

## 5.2 Immutabilité logique

- evidence en lecture seule ;
- hash à l’import ;
- possibilité de re-hasher ;
- résultats séparés des sources ;
- version d’outil enregistrée ;
- version des règles enregistrée ;
- version du normalizer enregistrée.

---

# 6. Tool Registry

Chaque outil possède un manifest.

```yaml
name: mftecmd
vendor: Eric Zimmerman
version: "x.y"
category: filesystem
inputs:
  - ntfs_mft
outputs:
  - csv
  - json
capabilities:
  - mft
  - ntfs
  - file_timestamps
execution:
  command: /opt/eztools/MFTECmd.exe
  timeout: 3600
security:
  network: false
```

Le registry doit gérer :

- installation ;
- version ;
- dépendances ;
- capabilities ;
- types d’entrée ;
- types de sortie ;
- besoins CPU/RAM ;
- besoin réseau ;
- compatibilité OS ;
- profils applicables ;
- statut « supporté / expérimental / legacy ».

---

# 7. Orchestrateur

## 7.1 Moteur de découverte

Entrée :

```text
Evidence
```

Sortie :

```text
Platform
Artifacts discovered
Recommended tools
Recommended profiles
```

Exemple :

```text
Windows disk image
 ├── NTFS
 ├── EVTX
 ├── Registry
 ├── Prefetch
 ├── Amcache
 ├── LNK
 └── browser artifacts
```

## 7.2 DAG d’analyse

Les analyses devront pouvoir être représentées comme un DAG :

```text
           Evidence
               │
        ┌──────┴──────┐
        ▼             ▼
    Discovery      Imaging
        │
 ┌──────┼──────────────┐
 ▼      ▼              ▼
EVTX   Registry       NTFS
 │      │              │
 ▼      ▼              ▼
Hayabusa RECmd        MFTECmd
 │      │              │
 └──────┼──────────────┘
        ▼
    Normalizer
        │
        ▼
     Timeline
```

## 7.3 Jobs

Statuts :

```text
PENDING
RUNNING
COMPLETED
FAILED
CANCELLED
TIMEOUT
```

Prévoir :

- parallélisation ;
- retry contrôlé ;
- timeout ;
- limite CPU/RAM ;
- annulation ;
- reprise après crash ;
- dépendances de jobs.

---

# 8. Profils d’analyse

Créer des profils déclaratifs.

## 8.1 `windows-triage`

Analyse rapide :

- identité système ;
- users ;
- processes ;
- EVTX essentiels ;
- Prefetch ;
- Registry ciblée ;
- MFT ;
- persistence ;
- detections rapides.

## 8.2 `windows-full`

Analyse étendue :

- tous les artefacts pertinents ;
- supertimeline ;
- règles de détection ;
- navigateur ;
- exécution ;
- persistance ;
- fichiers ;
- comptes ;
- réseau.

## 8.3 `ransomware`

Priorités :

- process creation ;
- PowerShell ;
- PsExec / services ;
- scheduled tasks ;
- RDP ;
- comptes ;
- fichiers récemment modifiés ;
- shadow copies ;
- crypto / mass file modifications ;
- IOC / YARA ;
- chronologie avant/après impact.

## 8.4 `persistence`

- services ;
- Run Keys ;
- scheduled tasks ;
- WMI ;
- startup folders ;
- browser extensions ;
- DLL search order / hijacking indicators ;
- autres mécanismes selon OS.

## 8.5 `browser`

- history ;
- downloads ;
- cookies ;
- sessions ;
- extensions ;
- cache ;
- SQLite.

## 8.6 `memory`

- process tree ;
- network ;
- modules ;
- suspicious handles ;
- persistence clues ;
- malware-focused plugins.

---

# 9. Timeline Engine

## 9.1 Objectif

Créer une timeline unique capable d’intégrer :

- Plaso ;
- Hayabusa ;
- EZ Tools ;
- Dissect ;
- Volatility ;
- network tooling ;
- journaux Linux ;
- artefacts custom.

## 9.2 Schéma commun

Champs recommandés :

```text
id
timestamp
end_timestamp
timezone
precision
host
user
source
artifact_type
event_type
action
object
process
pid
parent_pid
source_path
message
severity
confidence
tags
iocs
raw_reference
tool_reference
```

## 9.3 Formats

### Interne

- SQLite pour MVP ;
- JSONL pour interchange ;
- Parquet à étudier pour gros volumes.

### Export

- CSV ;
- JSON ;
- JSONL ;
- format compatible Timeline Explorer ;
- Timesketch ;
- éventuellement STIX pour IOC/intelligence.

---

# 10. Findings Engine

Le moteur de findings doit distinguer :

- événement brut ;
- détection ;
- corrélation ;
- hypothèse ;
- finding confirmé ;
- finding à examiner.

Chaque finding possède :

- sévérité ;
- confiance ;
- justification ;
- preuves ;
- règles déclenchées ;
- événements associés.

---

# 11. IOC / Threat Intelligence

## 11.1 IOC types

- IPv4 / IPv6 ;
- domain ;
- URL ;
- hash ;
- email ;
- filename ;
- mutex / service / task name ;
- registry path ;
- YARA hit ;
- Sigma rule hit.

## 11.2 Recherche

Pouvoir lancer :

```text
search_ioc(case, value)
hunt_hash(case, sha256)
hunt_domain(case, domain)
hunt_ip(case, ip)
hunt_filename(case, pattern)
```

## 11.3 Extensibilité

Étudier plus tard :

- YARA ;
- Sigma ;
- STIX/TAXII ;
- MISP ;
- ThreatFox / bases publiques selon politique et réseau ;
- enrichissement externe optionnel.

---

# 12. MCP Server

## 12.1 Philosophie

Le MCP doit exposer des **capacités forensic métier**, pas des commandes shell.

Interdit comme interface normale :

```text
run_command("...")
```

Préférer :

```text
analyze_evtx()
analyze_registry()
create_timeline()
search_timeline()
search_ioc()
get_finding()
generate_report()
```

## 12.2 Tools MCP minimum

### Cases

- `list_cases`
- `create_case`
- `get_case`
- `close_case`

### Evidence

- `list_evidence`
- `register_evidence`
- `verify_evidence`
- `get_evidence`
- `discover_evidence`

### Analysis

- `analyze_evidence`
- `run_profile`
- `run_tool`
- `get_job`
- `cancel_job`

### Timeline

- `create_timeline`
- `search_timeline`
- `get_timeline_event`
- `find_activity_window`

### Artefacts

- `search_artifacts`
- `get_artifact`
- `get_artifact_provenance`

### Hunting

- `search_ioc`
- `hunt_process`
- `hunt_persistence`
- `hunt_network_activity`

### Findings

- `list_findings`
- `get_finding`
- `correlate_findings`

### Reporting

- `generate_report`
- `export_timeline`
- `export_case`

## 12.3 MCP resources

Prévoir des ressources logiques :

```text
case://CASE-001
evidence://CASE-001/EVD-001
timeline://CASE-001
finding://CASE-001/F-001
report://CASE-001/report/final
```

## 12.4 MCP security

- authentification ;
- autorisation ;
- RBAC à terme ;
- allowlist des tools ;
- validation stricte des paramètres ;
- path confinement ;
- pas de shell arbitraire ;
- journalisation de toutes les opérations ;
- quotas ;
- limites de ressources.

---

# 13. API REST

## 13.1 Pourquoi

Le MCP et la CLI doivent reposer sur le même Core/API afin d’éviter trois implémentations différentes.

Architecture :

```text
CLI ─────┐
         ├──> Application Service ──> Core
MCP ─────┤
         │
API ─────┘
```

> **Règle fondamentale :** toute capacité ajoutée au Core doit être exposée **simultanément** via CLI et MCP. L'API REST suit comme troisième interface. Le MCP n'est pas un add-on tardif : c'est un citoyen de première classe, co-développé avec chaque fonctionnalité.

## 13.2 Endpoints initiaux

```text
GET    /api/v1/cases
POST   /api/v1/cases
GET    /api/v1/cases/{id}

POST   /api/v1/evidence
GET    /api/v1/evidence/{id}
POST   /api/v1/evidence/{id}/verify

POST   /api/v1/jobs
GET    /api/v1/jobs/{id}
POST   /api/v1/jobs/{id}/cancel

POST   /api/v1/timeline
GET    /api/v1/timeline/search

GET    /api/v1/artifacts
GET    /api/v1/findings
POST   /api/v1/reports
```

---

# 14. CLI

La CLI doit permettre l’utilisation complète sans MCP.

Exemples :

```bash
dfir cases list

dfir case create CASE-2026-001

dfir evidence add CASE-2026-001 /evidence/host01.E01

dfir evidence verify EVD-001

dfir discover EVD-001

dfir analyze EVD-001 --profile windows-full
dfir jobs list
dfir timeline build CASE-2026-001
dfir timeline search CASE-2026-001 --query "powershell.exe"
dfir findings list CASE-2026-001
dfir report generate CASE-2026-001
```

---

# 15. Conteneurisation

## 15.1 Ne pas faire un container monolithique par défaut

Architecture recommandée :

```text
docker compose
│
├── api / mcp
├── orchestrator
├── worker-default
├── worker-memory
├── worker-network
├── db
└── optional-ui
```

À terme, certains outils lourds ou incompatibles pourront avoir leur propre image.

## 15.2 Images

Exemple :

```text
dfir/core

dfir/worker-windows
  ├── EZ Tools
  ├── Hayabusa
  ├── Dissect
  ├── Plaso
  └── Chainsaw

dfir/worker-memory
  └── Volatility

dfir/worker-network
  ├── Zeek
  ├── TShark
  └── Suricata
```

## 15.3 Volumes

```text
./evidence:/evidence:ro
./cases:/cases
./config:/config:ro
./cache:/cache
```

---

# 16. Sécurité du conteneur

Le traitement d’une evidence doit être considéré comme un environnement potentiellement hostile.

## Mesures minimales

- `read_only` lorsque possible ;
- `no-new-privileges` ;
- `cap_drop: ALL` lorsque compatible ;
- aucune connexion réseau par défaut pour les workers offline ;
- filesystem de travail séparé ;
- limites CPU/RAM ;
- limites de taille des outputs ;
- timeouts ;
- path sandboxing ;
- pas d’écriture dans l’evidence ;
- scan des archives avant extraction lorsque pertinent ;
- protection contre path traversal ;
- interdiction des symlinks dangereux lors de certaines extractions ;
- logs d’audit.

---

# 17. Offline-first

Une plateforme DFIR doit pouvoir fonctionner sans Internet.

Prévoir :

- cache d’outils ;
- versions figées ;
- règles Sigma/YARA versionnées ;
- images Docker exportables ;
- documentation offline ;
- installation air-gapped à terme.

---

# 18. Configuration

Créer un système de configuration central :

```yaml
system:
  timezone: UTC
  workers: 4

storage:
  evidence: /evidence
  cases: /cases
  cache: /cache

security:
  network_default: deny
  max_memory_gb: 16

analysis:
  default_profile: windows-triage

mcp:
  enabled: true
```

---

# 19. Observabilité

Prévoir dès le début :

- logs structurés JSON ;
- correlation ID ;
- job ID ;
- case ID ;
- tool run ID ;
- métriques ;
- durée d’analyse ;
- CPU/RAM par job ;
- erreurs par outil.

À terme :

- Prometheus ;
- Grafana ;
- OpenTelemetry.

---

# 20. Tests

## 20.1 Unit tests

Tester :

- modèles ;
- validation ;
- registry ;
- path handling ;
- normalizers ;
- timeline ;
- permissions ;
- MCP schemas.

## 20.2 Integration tests

Pour chaque outil :

```text
known evidence
      ↓
expected tool output
      ↓
expected normalized artifact
```

## 20.3 Golden datasets

Créer un corpus de test contrôlé :

```text
tests/evidence/
├── windows/
├── linux/
├── memory/
└── network/
```

Chaque dataset doit avoir :

- hash ;
- description ;
- artefacts attendus ;
- résultats attendus ;
- éventuellement fixtures minimisées.

## 20.4 Regression tests

Lors d’une mise à jour d’un outil :

```text
old version output
        vs
new version output
```

Identifier les changements de schéma, de détection ou de parsing.

---

# 21. CI/CD

Pipeline cible :

```text
commit
  ↓
lint
  ↓
unit tests
  ↓
security checks
  ↓
build images
  ↓
integration tests
  ↓
golden dataset tests
  ↓
SBOM
  ↓
image scan
  ↓
publish
```

Outils possibles :

- GitHub Actions / GitLab CI ;
- Ruff / mypy / pytest ;
- Hadolint ;
- Trivy ;
- Syft ;
- Grype ;
- Gitleaks ;
- Cosign.

---

# 22. Supply-chain security

Chaque release doit pouvoir documenter :

- version du projet ;
- version de chaque outil ;
- hash des artefacts ;
- image digest ;
- SBOM ;
- provenance de build ;
- règles embarquées ;
- dépendances.

Objectif à terme :

```text
Release
   ├── OCI image
   ├── SBOM
   ├── checksums
   ├── manifest outils
   └── provenance
```

---

# 23. Reporting

## 23.1 Formats

- JSON ;
- CSV ;
- Markdown ;
- HTML ;
- PDF à terme.

## 23.2 Rapport forensic

Structure recommandée :

```text
1. Executive Summary
2. Scope
3. Evidence
4. Methodology
5. Tools and Versions
6. Timeline
7. Findings
8. Indicators of Compromise
9. Persistence
10. Process / Execution
11. Network Activity
12. Limitations
13. Appendix
14. Evidence hashes
```

## 23.3 Reproductibilité

Le rapport doit pouvoir afficher :

- profil exécuté ;
- outils ;
- versions ;
- timestamps ;
- hash evidence ;
- commandes logiques / paramètres ;
- limitations.

---

# 24. Web UI — phase ultérieure

Le Web UI ne doit pas bloquer le moteur.

Écrans cibles :

### Dashboard

- cases ;
- jobs ;
- findings ;
- workers ;
- erreurs.

### Case view

- evidence ;
- analyses ;
- artefacts ;
- timeline ;
- findings ;
- IOC ;
- reports.

### Timeline

- zoom ;
- filtres ;
- source ;
- host ;
- user ;
- severity ;
- type d’événement.

### Tool execution

- outil ;
- version ;
- temps ;
- statut ;
- logs ;
- outputs.

---

# 25. AI / Agent Layer

## 25.1 Rôle de l’IA

L’IA peut :

- proposer un plan d’analyse ;
- choisir un profil ;
- rechercher des événements ;
- corréler les résultats ;
- résumer une timeline ;
- regrouper les findings ;
- expliquer une détection ;
- générer un rapport.

L’IA ne doit pas :

- modifier l’evidence ;
- exécuter du shell arbitraire ;
- inventer des résultats forensic ;
- supprimer les traces de provenance ;
- considérer une hypothèse comme un fait sans preuves.

## 25.2 Exemple de workflow agentique

```text
User:
"Analyse cette machine pour une compromission Windows"

Agent
  ↓
register evidence
  ↓
verify hash
  ↓
discover artifacts
  ↓
select windows-full
  ↓
run tools
  ↓
build timeline
  ↓
search suspicious execution
  ↓
correlate network
  ↓
inspect persistence
  ↓
produce findings
  ↓
generate analyst summary
```

## 25.3 Human-in-the-loop

Certaines actions doivent nécessiter validation explicite :

- export externe ;
- partage d’une evidence ;
- modification d’une configuration sensible ;
- suppression ;
- enrichissement réseau externe ;
- lancement d’analyses très coûteuses.

---

# 26. Roadmap détaillée — MCP-first

> **Principe structurant :** le MCP est un citoyen de première classe. Chaque phase livre la capacité forensic **et** son exposition MCP simultanément. Il n’y a pas de « Phase MCP » isolée — le serveur MCP naît avec le projet et grandit avec lui.

```text
Phase N : nouvelle capacité
   ├── Service Layer (logique métier)
   ├── CLI command(s)
   ├── MCP tool(s)
   └── Tests (unit + MCP integration)
```

---

## Phase 0 — Cadrage / architecture

### Objectifs

- verrouiller le nom ;
- définir le périmètre MVP ;
- choisir le langage principal ;
- définir les contrats entre Core, tools, CLI, MCP et API ;
- définir les modèles JSON ;
- définir le protocole MCP (transport, auth, validation) ;
- définir la structure du repository.

### Livrables

- ADR initiales (dont ADR-011 MCP-first) ;
- architecture diagram triple-interface ;
- conventions code ;
- tool manifest schema ;
- evidence schema ;
- artifact schema ;
- timeline schema ;
- finding schema ;
- MCP tool naming conventions ;
- MCP security model.

### Exit criteria

- architecture documentée ;
- premier manifest validé ;
- contrat MCP tool ↔ Service Layer défini ;
- un tool peut être ajouté sans modification profonde du Core ni du MCP server.

---

## Phase 1 — Skeleton + MCP bootstrap

### Développer

- repository ;
- package Core ;
- configuration ;
- logging structuré ;
- CLI de base ;
- **MCP server skeleton** (transport, handshake, tool registration, validation, audit log) ;
- SQLite ;
- modèles Case / Evidence ;
- Docker de développement ;
- tests.

### CLI

```bash
defair --help
defair cases list
defair case create TEST
defair evidence add TEST sample.E01
```

### MCP — premiers tools

```text
list_cases
create_case
get_case
```

### Exit criteria

- une case peut être créée et persistée via CLI **et** via MCP ;
- le serveur MCP démarre, accepte des connexions et répond aux 3 tools ;
- un test d’intégration MCP passe.

---

## Phase 2 — Evidence Manager + MCP evidence

### Développer

- import ;
- hashing ;
- validation ;
- read-only handling ;
- metadata ;
- evidence types ;
- provenance initiale.

### CLI

```bash
defair evidence add CASE-001 /evidence/host01.E01
defair evidence verify EVD-001
defair evidence inspect EVD-001
defair evidence list CASE-001
```

### MCP — tools ajoutés

```text
register_evidence
verify_evidence
get_evidence
list_evidence
discover_evidence
```

### MCP — resources ajoutées

```text
case://CASE-001
evidence://CASE-001/EVD-001
```

### Exit criteria

- une evidence importée est identifiable, hashée et immuable logiquement ;
- toutes les opérations evidence sont disponibles via CLI **et** MCP ;
- un agent peut enregistrer et vérifier une evidence via MCP.

---

## Phase 3 — Tool Registry + MCP tool execution

### Développer

- manifest YAML/JSON ;
- detection version ;
- capabilities ;
- input/output types ;
- dependency model ;
- command wrapper ;
- tool health check ;
- job model (PENDING → RUNNING → COMPLETED/FAILED) ;
- **MCP run_tool / get_job**.

### Premier outil

Commencer avec **Dissect** (Python natif, pas de problème de runtime) afin de valider tout le modèle.

### CLI

```bash
defair tools list
defair tools info dissect
defair tools health
defair run dissect EVD-001 --output json
defair jobs list
defair jobs status JOB-001
```

### MCP — tools ajoutés

```text
list_tools
get_tool_info
run_tool
get_job
cancel_job
list_jobs
```

### Exit criteria

- un outil peut être exécuté via CLI **et** MCP ;
- le job est traçable (statut, durée, exit code, outputs) ;
- le manifest est validé et le health check fonctionne.

---

## Phase 4 — Dissect integration + MCP discovery

### Développer

- discovery (identification d’hôte, plateforme, artefacts présents) ;
- host identification ;
- filesystem access ;
- extraction ;
- artefacts ;
- normalizers Dissect.

### MCP — tools ajoutés

```text
discover_evidence       (lance Dissect discovery, retourne plateforme + artefacts)
get_host_info           (informations d’identification de l’hôte)
list_discovered_artifacts
```

### Exit criteria

- Dissect peut identifier un hôte Windows et lister ses artefacts ;
- un agent MCP peut appeler `discover_evidence` et obtenir la liste des artefacts analysables ;
- la découverte alimente le choix d’outils.

---

## Phase 5 — EZ Tools Foundation + MCP analyze

### Objectif

Créer le module EZ Tools et exposer les analyses spécialisées via MCP.

### Sous-phases

#### 5.1 Packaging

- définir stratégie de distribution ;
- version pinning ;
- dépendances .NET ;
- wrapper ;
- health checks.

#### 5.2 First tools

Priorité :

1. MFTECmd
2. EvtxECmd
3. RECmd
4. PECmd
5. AmcacheParser
6. AppCompatCacheParser
7. LECmd
8. JLECmd
9. RBCmd
10. SBECmd
11. SQLECmd
12. autres selon besoins.

#### 5.3 GUI-only tools

- documenter ;
- identifier les exports possibles ;
- ne pas bloquer le serveur headless ;
- éventuellement fournir des artefacts compatibles avec les clients desktop.

### MCP — tools ajoutés

```text
analyze_mft             (wrapper MFTECmd)
analyze_evtx            (wrapper EvtxECmd)
analyze_registry        (wrapper RECmd)
analyze_prefetch        (wrapper PECmd)
analyze_amcache         (wrapper AmcacheParser)
analyze_shimcache       (wrapper AppCompatCacheParser)
analyze_lnk             (wrapper LECmd)
analyze_jumplist        (wrapper JLECmd)
```

> Chaque MCP tool d’analyse encapsule : sélection de l’outil → exécution → capture outputs → provenance → retour structuré.

### Exit criteria

- les artefacts clés Windows sont analysables via le moteur ;
- chaque analyse est disponible via CLI **et** MCP ;
- un agent peut enchaîner `discover_evidence` → `analyze_evtx` sans intervention humaine.

---

## Phase 6 — Hayabusa integration + MCP hunting

### Développer

- EVTX discovery ;
- ruleset management ;
- execution profiles ;
- JSONL ingestion ;
- normalizer ;
- severity mapping ;
- finding creation.

### MCP — tools ajoutés

```text
hunt_evtx               (Hayabusa avec règles Sigma)
list_detections          (résultats Hayabusa normalisés)
get_detection            (détail d’une détection)
```

### Exit criteria

- un dossier EVTX produit des artefacts normalisés et des findings exploitables ;
- un agent MCP peut lancer un hunt et consulter les détections.

---

## Phase 7 — Timeline Engine + MCP timeline

### Développer

- unified schema ;
- SQLite backend ;
- JSONL ;
- CSV ;
- Timeline Explorer-compatible export ;
- Timesketch-compatible export ;
- search ;
- filters ;
- window analysis ;
- intégration des sorties EZ Tools + Hayabusa + Dissect.

### CLI

```bash
defair timeline build CASE-001
defair timeline search CASE-001 --query "powershell.exe"
defair timeline search CASE-001 --from "2026-01-15" --to "2026-01-16"
defair timeline export CASE-001 --format csv
```

### MCP — tools ajoutés

```text
build_timeline
search_timeline
get_timeline_event
find_activity_window
export_timeline
```

### MCP — resources ajoutées

```text
timeline://CASE-001
```

### Exit criteria

- les événements multi-sources peuvent être consultés dans une timeline commune ;
- un agent MCP peut construire, chercher et exporter une timeline.

---

## Phase 8 — Findings & IOC Engine + MCP findings

### Développer

- severity ;
- confidence ;
- IOC store ;
- correlation ;
- Sigma references ;
- YARA support ;
- evidence links.

### MCP — tools ajoutés

```text
list_findings
get_finding
correlate_findings
search_ioc
hunt_hash
hunt_domain
hunt_ip
hunt_filename
get_artifact_provenance
```

### MCP — resources ajoutées

```text
finding://CASE-001/F-001
```

### Exit criteria

- un analyste peut remonter d’un finding jusqu’à l’artefact source et à l’evidence ;
- un agent MCP peut naviguer la chaîne de provenance complète.

---

## Phase 9 — Orchestrator + MCP profiles

### Développer

- DAG ;
- dependency handling ;
- worker scheduling ;
- parallel jobs ;
- retry ;
- timeout ;
- cancellation ;
- resource limits ;
- profils déclaratifs YAML.

### Profiles

- `windows-triage`
- `windows-full`
- `persistence`
- `ransomware`
- `browser`
- `memory`

### CLI

```bash
defair analyze EVD-001 --profile windows-full
defair analyze EVD-001 --profile ransomware
```

### MCP — tools ajoutés

```text
run_profile             (lance un profil complet : discovery → tools → timeline → findings)
list_profiles
get_profile
analyze_evidence        (alias haut niveau : discover + select profile + run)
```

### Exit criteria

- un seul appel `run_profile` via MCP déclenche une chaîne complète ;
- le DAG gère les dépendances et la parallélisation ;
- c’est le **MVP MCP complet** : un agent peut conduire une investigation Windows de bout en bout.

---

## Phase 10 — Plaso integration + supertimeline

### Développer

- parsers ;
- storage ;
- supertimeline ;
- export ;
- normalization ;
- timezone management ;
- intégration avec le Timeline Engine existant.

### MCP — tools enrichis

```text
build_timeline          (enrichi : inclut maintenant Plaso comme source)
```

### Exit criteria

- le projet peut produire une supertimeline multi-source ;
- les résultats Plaso s’intègrent dans la timeline unifiée existante.

---

## Phase 11 — Reporting + MCP reports

### Développer

- templates Markdown ;
- HTML ;
- exports ;
- evidence appendix ;
- tool inventory ;
- findings appendix ;
- reproducibility section.

### MCP — tools ajoutés

```text
generate_report
export_case
list_reports
```

### MCP — resources ajoutées

```text
report://CASE-001/report/final
```

### Exit criteria

- une case complète produit un rapport exploitable ;
- un agent MCP peut générer et récupérer un rapport.

---

## Phase 12 — API REST

### Développer

- OpenAPI spec ;
- auth ;
- tous les endpoints miroir du MCP et de la CLI ;
- documentation Swagger.

### Architecture vérifiée

```text
CLI ─────┐
         ├──> Application Service ──> Core
MCP ─────┤
         │
API ─────┘
```

### Exit criteria

- CLI, MCP et API utilisent les mêmes services applicatifs ;
- aucune logique métier ne vit dans les couches d’interface.

---

## Phase 13 — Volatility + Memory + MCP memory

### Développer

- packaging ;
- plugin registry ;
- dump discovery ;
- result normalization ;
- process/network views ;
- timeline integration.

### MCP — tools ajoutés

```text
analyze_memory
list_processes
list_network_connections
hunt_memory
```

### Exit criteria

- une memory image peut être intégrée dans la même case qu’une image disque ;
- un agent MCP peut analyser la mémoire et croiser avec les artefacts disque.

---

## Phase 14 — Network DFIR + MCP network

### Développer

- PCAP ingestion ;
- TShark ;
- Zeek ;
- Suricata ;
- network timeline ;
- IOC extraction ;
- host/network correlation.

### MCP — tools ajoutés

```text
analyze_pcap
hunt_network_activity
list_connections
list_dns_queries
detect_beaconing
```

### Exit criteria

- une investigation peut corréler host + memory + PCAP ;
- un agent MCP peut piloter l’analyse réseau.

---

## Phase 15 — Linux DFIR + MCP linux

### Développer

- journald ;
- SSH ;
- auth ;
- cron ;
- systemd ;
- shell history ;
- users ;
- persistence ;
- Docker/container artifacts.

### MCP — tools ajoutés

```text
analyze_linux
hunt_linux_persistence
list_linux_users
list_linux_services
```

### Exit criteria

- le workflow triage Linux atteint un niveau de maturité comparable au workflow Windows de base ;
- un agent MCP peut conduire une investigation Linux.

---

## Phase 16 — MCP advanced + security hardening

### Développer

- RBAC MCP ;
- audit trail complet ;
- quotas par client MCP ;
- rate limiting ;
- allowlist dynamique des tools ;
- MCP prompts (workflows guidés) ;
- MCP sampling (demande de validation humaine) ;
- secret management ;
- worker isolation ;
- SBOM ;
- image signing ;
- vulnerability scanning.

### Exit criteria

- le MCP est production-ready avec contrôle d’accès ;
- un déploiement multi-utilisateurs est possible ;
- la surface d’attaque MCP est documentée et contrôlée.

---

## Phase 17 — Web UI

### Développer

- authentication ;
- cases ;
- jobs ;
- findings ;
- timeline ;
- evidence ;
- tool runs ;
- report viewer.

### Exit criteria

Un analyste peut utiliser la plateforme sans CLI.

---

## Phase 18 — AI / Agent orchestration avancée

### Développer

- investigation planner ;
- tool selection ;
- evidence-aware reasoning ;
- timeline summarization ;
- finding correlation ;
- analyst notes ;
- report drafting ;
- MCP prompts pour workflows agentiques.

### Garde-fous

- jamais d’accès brut au shell ;
- jamais de mutation evidence ;
- provenance obligatoire ;
- distinction faits / hypothèses ;
- validation humaine pour actions sensibles.

---

# 27. Versioning produit — MCP-first

> Chaque version inclut sa surface MCP correspondante. Le MCP n'a pas de version dédiée : il grandit avec le produit.

## v0.1 — Core + MCP bootstrap

- Case + Evidence + hashing + SQLite
- CLI de base
- **MCP server** : `list_cases`, `create_case`, `register_evidence`, `verify_evidence`
- Tool Registry
- Docker dev

## v0.2 — Windows foundation + MCP discovery & analysis

- Dissect discovery
- EZ Tools de base (MFTECmd, EvtxECmd, RECmd, PECmd)
- Normalisation
- **MCP** : `discover_evidence`, `run_tool`, `analyze_evtx`, `analyze_mft`, `analyze_registry`, `get_job`

## v0.3 — Detection + Timeline + MCP hunting

- Hayabusa
- Timeline Engine
- Findings Engine
- **MCP** : `hunt_evtx`, `build_timeline`, `search_timeline`, `list_findings`, `search_ioc`

## v0.4 — Orchestration + MCP profiles

- Profils déclaratifs
- DAG + workers + jobs parallèles
- Plaso (supertimeline)
- **MCP** : `run_profile`, `analyze_evidence`, `list_profiles`
- **Jalon : MVP MCP complet** — un agent peut conduire une investigation Windows de bout en bout

## v0.5 — Reporting + API REST

- Rapports Markdown / HTML
- API REST (OpenAPI)
- **MCP** : `generate_report`, `export_case`, `export_timeline`

## v0.6 — Memory + Network + MCP étendu

- Volatility
- TShark / Zeek / Suricata
- **MCP** : `analyze_memory`, `analyze_pcap`, `hunt_network_activity`

## v0.7 — Linux + MCP linux

- Linux DFIR
- Docker artifacts
- **MCP** : `analyze_linux`, `hunt_linux_persistence`

## v0.8 — UI

- Dashboard
- Timeline viewer
- Findings viewer

## v0.9 — Hardening + MCP production

- RBAC MCP
- Audit trail
- Quotas / rate limiting
- Supply chain security
- SBOM / image signing

## v1.0 — DEFAIR

Critères :

- workflow forensic complet ;
- Windows mature ;
- **MCP stable et production-ready** ;
- API stable ;
- evidence provenance complète ;
- timeline unifiée ;
- reporting ;
- tests de non-régression ;
- documentation ;
- images reproductibles ;
- installation documentée ;
- **un agent IA peut conduire une investigation complète via MCP sans shell**.

---

# 28. Backlog priorisé — MCP-first

## P0 — Fondation (Core + CLI + MCP skeleton)

- [ ] architecture
- [ ] modèles de données
- [ ] **MCP server bootstrap** (transport, handshake, tool registration, validation)
- [ ] evidence manager
- [ ] hashing
- [ ] provenance
- [ ] Tool Registry
- [ ] wrapper d’exécution
- [ ] Docker de base
- [ ] CLI
- [ ] SQLite
- [ ] tests (unit + MCP integration)
- [ ] **MCP tools** : `list_cases`, `create_case`, `register_evidence`, `verify_evidence`

## P1 — MVP forensic Windows + MCP analysis

- [ ] Dissect + MCP `discover_evidence`
- [ ] MFTECmd + MCP `analyze_mft`
- [ ] EvtxECmd + MCP `analyze_evtx`
- [ ] RECmd + MCP `analyze_registry`
- [ ] PECmd + MCP `analyze_prefetch`
- [ ] AmcacheParser + MCP `analyze_amcache`
- [ ] AppCompatCacheParser + MCP `analyze_shimcache`
- [ ] LECmd + MCP `analyze_lnk`
- [ ] Hayabusa + MCP `hunt_evtx`
- [ ] timeline + MCP `build_timeline`, `search_timeline`
- [ ] profiles + MCP `run_profile`, `analyze_evidence`
- [ ] findings + MCP `list_findings`, `search_ioc`
- [ ] Plaso (supertimeline)

## P2 — Reporting + API REST

- [ ] reporting + MCP `generate_report`, `export_case`
- [ ] REST API (OpenAPI)
- [ ] audit complet

## P3 — Extension forensic + MCP étendu

- [ ] Volatility + MCP `analyze_memory`
- [ ] Chainsaw
- [ ] YARA
- [ ] Sigma
- [ ] PCAP + MCP `analyze_pcap`
- [ ] Zeek + MCP `hunt_network_activity`
- [ ] TShark
- [ ] Suricata
- [ ] Linux DFIR + MCP `analyze_linux`

## P4 — Produit

- [ ] Web UI
- [ ] RBAC MCP
- [ ] observabilité
- [ ] SBOM
- [ ] signed releases
- [ ] offline bundle

## P5 — IA avancée

- [ ] investigation planner (MCP prompts)
- [ ] correlation assistant
- [ ] timeline summarizer
- [ ] report assistant
- [ ] analyst copilot

---

# 29. Structure de repository cible

```text
dfir-swiss-knife/
│
├── apps/
│   ├── api/
│   ├── mcp/
│   ├── cli/
│   └── web/
│
├── core/
│   ├── cases/
│   ├── evidence/
│   ├── artifacts/
│   ├── timeline/
│   ├── findings/
│   ├── provenance/
│   ├── ioc/
│   ├── jobs/
│   └── schemas/
│
├── orchestrator/
│   ├── planner/
│   ├── scheduler/
│   ├── workers/
│   └── profiles/
│
├── tools/
│   ├── eztools/
│   │   ├── mftecmd/
│   │   ├── recmd/
│   │   ├── evtxecmd/
│   │   ├── pecmd/
│   │   ├── amcacheparser/
│   │   └── ...
│   │
│   ├── dissect/
│   ├── hayabusa/
│   ├── plaso/
│   ├── volatility/
│   ├── chainsaw/
│   ├── tshark/
│   ├── zeek/
│   └── suricata/
│
├── normalizers/
│   ├── eztools/
│   ├── dissect/
│   ├── hayabusa/
│   ├── plaso/
│   └── volatility/
│
├── profiles/
│   ├── windows-triage.yaml
│   ├── windows-full.yaml
│   ├── ransomware.yaml
│   ├── persistence.yaml
│   ├── browser.yaml
│   ├── memory.yaml
│   └── linux-triage.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── golden/
│   └── fixtures/
│
├── deployment/
│   ├── docker/
│   ├── compose/
│   └── kubernetes/
│
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── tools/
│   ├── mcp/
│   ├── api/
│   └── operations/
│
├── scripts/
├── pyproject.toml
├── docker-compose.yml
└── README.md
```

---

# 30. Architecture Decision Records à créer

- ADR-001 — langage principal
- ADR-002 — SQLite comme backend MVP
- ADR-003 — Docker Compose comme déploiement MVP
- ADR-004 — modèle d’evidence
- ADR-005 — modèle de provenance
- ADR-006 — Tool Registry
- ADR-007 — normalisation des artefacts
- ADR-008 — timeline interne
- ADR-009 — stratégie EZ Tools
- ADR-010 — séparation GUI / headless
- ADR-011 — MCP sans shell arbitraire
- ADR-012 — stratégie workers
- ADR-013 — stockage des outputs
- ADR-014 — offline-first
- ADR-015 — supply-chain security
- ADR-016 — versioning des règles Sigma/YARA
- ADR-017 — modèle Findings
- ADR-018 — AI human-in-the-loop

---

# 31. Risques principaux

## Risque 1 — explosion du périmètre

### Problème

« Tous les outils forensic » peut rendre le projet impossible à maintenir.

### Mitigation

- tool maturity tiers ;
- modules indépendants ;
- priorité à Windows/DFIR ;
- profiles ;
- contribution system.

---

## Risque 2 — GUI dans Docker

### Problème

Certains outils sont conçus pour Windows desktop.

### Mitigation

- séparer GUI/headless ;
- privilégier CLI ;
- fournir exports compatibles ;
- documenter les outils desktop comme clients externes.

---

## Risque 3 — divergence des formats

### Problème

Chaque outil produit des outputs différents.

### Mitigation

Normalization layer obligatoire + tests golden.

---

## Risque 4 — dérive des versions

### Problème

Les outils changent de format et de comportement.

### Mitigation

- pinning ;
- manifests ;
- regression datasets ;
- version matrix.

---

## Risque 5 — sécurité du worker

### Problème

Une evidence malveillante peut contenir des fichiers ou structures hostiles.

### Mitigation

Sandboxing + read-only + limites + isolation + aucun réseau par défaut.

---

## Risque 6 — MCP trop puissant

### Problème

Un agent pourrait transformer le système en exécution distante arbitraire.

### Mitigation

Tool-oriented API, allowlists, validation et audit.

---

# 32. Definition of Done — outil intégré

Un outil n’est considéré comme « intégré » que si :

- [ ] packaging déterministe ;
- [ ] version détectable ;
- [ ] manifest présent ;
- [ ] wrapper présent ;
- [ ] timeout configuré ;
- [ ] resource limits documentées ;
- [ ] input types définis ;
- [ ] output types définis ;
- [ ] parser/normalizer présent si nécessaire ;
- [ ] provenance conservée ;
- [ ] logs capturés ;
- [ ] test d’intégration présent ;
- [ ] fixture ou dataset de régression présent ;
- [ ] documentation présente.

---

# 33. Definition of Done — feature

Une fonctionnalité est terminée lorsque :

- [ ] spécification définie ;
- [ ] modèle de données défini ;
- [ ] CLI command(s) définie(s) ;
- [ ] **MCP tool(s) défini(s) et implémenté(s)** ;
- [ ] implémentation faite (Service Layer) ;
- [ ] tests unitaires ;
- [ ] tests d’intégration ;
- [ ] **tests MCP integration** ;
- [ ] sécurité validée ;
- [ ] logs structurés ;
- [ ] documentation ;
- [ ] exemple CLI **et** exemple MCP ;
- [ ] migration si nécessaire ;
- [ ] backward compatibility vérifiée.

---

# 34. Premier jalon concret

Le premier véritable objectif doit être **MVP Windows DFIR** :

```text
E01 / RAW
   │
   ▼
Evidence Manager
   │
   ▼
Dissect discovery
   │
   ├── NTFS → MFTECmd
   ├── EVTX → EvtxECmd + Hayabusa
   ├── Registry → RECmd
   ├── Prefetch → PECmd
   └── Timeline → Plaso
            │
            ▼
       Normalization
            │
            ▼
       Unified Timeline
            │
       ┌────┴─────┐
       ▼          ▼
    Findings      IOCs
       │          │
       └────┬─────┘
            ▼
          MCP
```

### Ce MVP doit permettre

```text
1. créer une case
2. enregistrer une evidence
3. vérifier son hash
4. découvrir les artefacts
5. lancer un profil Windows
6. exécuter EZ Tools + Dissect + Hayabusa + Plaso
7. récupérer les outputs
8. normaliser les artefacts
9. construire une timeline
10. chercher des événements
11. afficher les findings
12. produire un rapport
13. faire exactement les mêmes opérations via MCP
```

---

# 35. Vision V1 finale

```text
                      ┌──────────────────────┐
                      │ Analyst / AI / SOC   │
                      └──────────┬───────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                   Web                       MCP
                    │                         │
                    └────────────┬────────────┘
                                 │
                         API / Core Engine
                                 │
                    ┌────────────┴────────────┐
                    │     Orchestrator        │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
   Evidence               Tool Registry              Jobs
        │                        │                        │
        │          ┌─────────────┼─────────────┐          │
        │          │             │             │          │
        ▼          ▼             ▼             ▼          ▼
     Dissect   EZ Tools      Hayabusa       Plaso    Volatility
        │          │             │             │          │
        └──────────┴─────────────┴─────────────┴──────────┘
                                 │
                         Normalization Layer
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
           Timeline           Findings             IOC
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                     Reporting / Export / Search
```

Le résultat final n’est donc pas simplement :

> **« Docker avec 50 outils forensic »**

mais :

> **« Une plateforme DFIR reproductible capable d’orchestrer de nombreux moteurs forensic, d’unifier leurs résultats et d’exposer l’investigation à un humain ou à un agent via CLI, API et MCP. »**

---

# 36. Priorité recommandée — MCP-first

Pour éviter de se perdre dans le nombre d’outils, la priorité de développement est :

```text
1. Core / Evidence / MCP skeleton        ← MCP naît ici
2. Tool Registry / Jobs / MCP run_tool
3. Dissect / MCP discover_evidence
4. EZ Tools Windows core / MCP analyze_*
5. Hayabusa / MCP hunt_evtx
6. Timeline Engine / MCP timeline
7. Findings & IOC / MCP findings
8. Orchestrator / MCP profiles           ← MVP MCP complet
9. Plaso (supertimeline)
10. Reporting / MCP reports
11. API REST
12. Volatility / MCP memory
13. Network / MCP network
14. Linux / MCP linux
15. MCP hardening (RBAC, quotas, audit)
16. UI
17. AI advanced / MCP prompts
```

> **Jalon critique :** à la fin du point 8, un agent IA peut conduire une investigation Windows complète via MCP sans accès shell.

---

# 37. Métriques de réussite

## MVP

- une evidence Windows analysable sans intervention manuelle ;
- plusieurs outils exécutables via un profile ;
- résultats traçables ;
- timeline unifiée ;
- findings reliés aux sources ;
- usage complet via CLI ;
- usage complet via MCP.

## V1

- plusieurs types d’evidence ;
- Windows + Linux + mémoire + réseau ;
- dizaines d’outils gérés via Tool Registry ;
- analyse parallèle ;
- exports standards ;
- rapports reproductibles ;
- tests golden ;
- installation offline ;
- sécurité renforcée ;
- API stable ;
- MCP stable.

---

# 38. Conclusion

La stratégie recommandée est de construire le projet **par capacités**, et non par accumulation de binaires. Le MCP est un **pilier structurant** du projet, co-développé avec chaque fonctionnalité dès le jour 1.

Les briques essentielles sont :

```text
Evidence + MCP evidence
       +
Tool Registry + MCP run_tool
       +
Normalizers
       +
Timeline + MCP timeline
       +
Findings + MCP findings
       +
Orchestrator + MCP profiles
       +
Provenance
       =
DEFAIR — MCP-first DFIR Workbench
```

Architecture triple-interface :

```text
Chaque capacité
       │
  ┌────┼────┐
  ▼    ▼    ▼
 CLI  MCP  API
  │    │    │
  └────┼────┘
       ▼
  Service Layer
       ▼
     Core
```

Les outils comme **EZ Tools, Dissect, Hayabusa, Plaso et Volatility** deviennent alors des moteurs interchangeables au sein d’une architecture cohérente.

Le premier objectif concret doit rester volontairement limité : **une chaîne Windows DFIR complète, reproductible et pilotable par MCP**. Le MCP n’est pas un ajout tardif — c’est l’interface par laquelle un agent IA conduit l’investigation, et elle doit être aussi mature que la CLI dès le MVP.

Une fois cette chaîne solide, l’ajout du memory forensics, du réseau, de Linux et d’une interface Web devient une extension du framework plutôt qu’un nouveau projet à chaque fois. Chaque extension apporte simultanément ses outils **et** ses MCP tools.
