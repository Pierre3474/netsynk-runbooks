# netsynk-runbooks

Extraits **réels et anonymisés** d'une plateforme cloud privée que j'exploite
en production depuis 2023 : cluster Proxmox en haute disponibilité, Kubernetes
monté par kubeadm, PostgreSQL répliqué, supervision de bout en bout.

Les dépôts d'exploitation restent privés — ils contiennent des adresses, des
noms de machines et des références de secrets. Ce dépôt-ci existe pour montrer
**comment c'est écrit**, pas pour être déployé tel quel.

Contexte détaillé et arbitrages : [portfolio.netsynk.eu](https://portfolio.netsynk.eu)

## Comment ces fichiers sont produits

Ils ne sont pas copiés à la main. `tools/sanitize.py` lit les fichiers dans les
dépôts privés, applique une table de substitution, puis **refuse d'écrire** tout
fichier où survit une IP privée, un domaine interne, une clé ou un secret en
clair.

```bash
python3 tools/sanitize.py
```

Le script sort en erreur si un extrait échoue au contrôle : impossible de
publier une fuite par distraction. Un secret ne se relit pas, il se vérifie.

Substitutions appliquées :

| Réel | Publié | Pourquoi |
|---|---|---|
| IP du LAN | `192.0.2.x` | RFC 5737, réservée à la documentation |
| Tunnel entre sites | `198.51.100.x` | RFC 5737 |
| IP publique du VPS | `203.0.113.x` | RFC 5737 |
| `*.netsynk.eu` | `*.example.com` | RFC 2606 |
| `*.netsynk.local` | `*.example.internal` | RFC 2606 |
| Noms d'hôtes, emails, MAC | placeholders | données identifiantes |

## Contenu

### `kubernetes/`

| Fichier | Ce qu'il montre |
|---|---|
| `postgres-cluster.yaml` | Cluster PostgreSQL à 3 instances via CloudNativePG. La bascule du primaire est gérée par l'opérateur, et testée à la main — une restauration prend des minutes, une bascule des secondes. |
| `cloudnativepg-cluster.yaml` | Seconde déclinaison, avec le paramétrage du stockage et des sauvegardes. |
| `metallb-pool.yaml` | Pools d'adresses séparés pour l'ingress interne et l'ingress public : ce qui n'a pas à être exposé ne l'est pas. |
| `cilium-application.yaml` | Cilium en CNI, déployé en GitOps. Choisi contre Flannel pour les politiques réseau applicatives — le reste de l'infra est segmenté, laisser les pods se parler librement aurait annulé ce travail. |
| `monitoring-application.yaml` | Pile Prometheus / Grafana. Les identifiants viennent d'un `existingSecret`, jamais du manifeste. |

### `ansible/`

| Fichier | Ce qu'il montre |
|---|---|
| `site.yml` | Point d'entrée : rôles appliqués par groupe de machines. |
| `roles/common/tasks/main.yml` | Socle appliqué à tous les nœuds. |
| `roles/control-plane/tasks/main.yml` | Préparation d'un nœud de plan de contrôle avant `kubeadm`. |

### `monitoring/`

| Fichier | Ce qu'il montre |
|---|---|
| `promtail-node.yml` | Collecte des journaux d'un nœud Proxmox vers Loki. Les journaux sont centralisés parce qu'un incident se relit après coup, pas pendant. |

## Ce que ce dépôt ne contient pas

Volontairement : aucun secret, même chiffré ; aucun plan d'adressage réel ;
aucune règle de pare-feu ; aucun inventaire de machines. La valeur d'un runbook
est dans sa structure, pas dans ses adresses.

## Licence

MIT — voir [LICENSE](LICENSE). Reprenez ce qui vous sert.
