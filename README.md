# netsynk-runbooks

Extraits anonymisés de la configuration de ma plateforme personnelle, en service depuis 2023 : un cluster Proxmox de trois nœuds, un cluster Kubernetes installé avec kubeadm, la supervision.

Les dépôts d'exploitation sont privés, parce qu'ils contiennent des adresses, des noms de machines et des références de secrets. Ce dépôt montre comment les fichiers sont écrits. Il n'est pas prévu pour être déployé tel quel.

Présentation du projet : [portfolio.netsynk.eu](https://portfolio.netsynk.eu)

## Comment les fichiers sont produits

`tools/sanitize.py` lit les fichiers dans les dépôts privés et applique une table de substitution. Il refuse d'écrire un fichier qui contient encore une IP privée, un domaine interne, une clé ou un secret en clair, et sort alors en erreur.

```bash
python3 tools/sanitize.py
```

Substitutions appliquées :

| Réel | Publié | Référence |
|---|---|---|
| IP du LAN | `192.0.2.x` | RFC 5737, plage réservée à la documentation |
| Tunnel entre sites | `198.51.100.x` | RFC 5737 |
| IP publique du VPS | `203.0.113.x` | RFC 5737 |
| `*.netsynk.eu` | `*.example.com` | RFC 2606 |
| `*.netsynk.local` | `*.example.internal` | RFC 2606 |
| Noms d'hôtes, e-mails, adresses MAC | valeurs factices | données identifiantes |

Un workflow GitHub Actions (`.github/workflows/no-secrets.yml`) refait ce contrôle à chaque push.

## Contenu

### `kubernetes/`

| Fichier | Contenu |
|---|---|
| `postgres-cluster.yaml` | Cluster PostgreSQL de 3 instances avec CloudNativePG. Utilisé jusqu'en août 2026 : la base a depuis été déplacée dans un conteneur dédié, hors du cluster. |
| `cloudnativepg-cluster.yaml` | Variante avec le paramétrage du stockage et des sauvegardes. |
| `metallb-pool.yaml` | Deux pools d'adresses : un pour l'ingress interne, un pour l'ingress public. |
| `cilium-application.yaml` | Cilium comme CNI, déployé par ArgoCD. Choisi pour ses politiques réseau entre pods. |
| `monitoring-application.yaml` | Prometheus et Grafana. Les identifiants viennent d'un `existingSecret`. |

### `ansible/`

| Fichier | Contenu |
|---|---|
| `site.yml` | Point d'entrée : rôles appliqués par groupe de machines. |
| `roles/common/tasks/main.yml` | Configuration commune à tous les nœuds. |
| `roles/control-plane/tasks/main.yml` | Préparation d'un nœud de plan de contrôle avant `kubeadm`. |

### `monitoring/`

| Fichier | Contenu |
|---|---|
| `promtail-node.yml` | Envoi des journaux d'un nœud Proxmox vers Loki. |

## Ce que le dépôt ne contient pas

Aucun secret, même chiffré. Pas de plan d'adressage réel, pas de règles de pare-feu, pas d'inventaire de machines.

## Licence

MIT, voir [LICENSE](LICENSE).
