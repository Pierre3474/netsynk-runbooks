#!/usr/bin/env python3
"""Extrait des fichiers réels depuis les dépôts privés, en les anonymisant.

    python3 tools/sanitize.py

Le principe : les extraits publiés sont produits par un script, jamais
copiés à la main. Toute donnée identifiante passe par la table ci-dessous,
et le script refuse d'écrire un fichier qui contient encore un motif
sensible — le contrôle est donc automatique, pas une relecture optimiste.

Plages utilisées : 192.0.2.0/24 (RFC 5737, réservée à la documentation) et
les domaines example.com / example.internal (RFC 2606).
"""

import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
PRIVATE = HERE.parent  # …/homelab

# fichier source (relatif à …/homelab) → destination dans ce dépôt
EXTRACTS = {
    "netsynk-gitops/manifests/databases/postgres-cluster.yaml": "kubernetes/postgres-cluster.yaml",
    "netsynk-gitops/manifests/metallb/pool.yaml": "kubernetes/metallb-pool.yaml",
    "netsynk-gitops/apps/cilium.yaml": "kubernetes/cilium-application.yaml",
    "netsynk-gitops/apps/monitoring.yaml": "kubernetes/monitoring-application.yaml",
    "netsynk-gitops/ansible/roles/common/tasks/main.yml": "ansible/roles/common/tasks/main.yml",
    "netsynk-gitops/ansible/roles/control-plane/tasks/main.yml": "ansible/roles/control-plane/tasks/main.yml",
    "netsynk-gitops/ansible/site.yml": "ansible/site.yml",
    "homelab-pve/monitoring/promtail/config-pve-node.yml": "monitoring/promtail-node.yml",
    "homelab-pve/k8s/infra/databases/cloudnativepg-cluster.yaml": "kubernetes/cloudnativepg-cluster.yaml",
}

# Ordre important : du plus spécifique au plus général.
RULES = [
    (re.compile(r"\b88\.96\.49\.57\b"), "203.0.113.10"),          # VPS public
    (re.compile(r"\b10\.99\.0\.(\d+)\b"), r"198.51.100.\1"),      # tunnel
    (re.compile(r"\b10\.\d+\.\d+\.(\d+)\b"), r"192.0.2.\1"),      # LAN interne
    (re.compile(r"\b192\.168\.\d+\.(\d+)\b"), r"192.0.2.\1"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.(\d+)\b"), r"192.0.2.\1"),
    (re.compile(r"[a-z0-9-]+\.netsynk\.local"), "host.example.internal"),
    (re.compile(r"netsynk\.local"), "example.internal"),
    (re.compile(r"[a-z0-9-]+\.netsynk\.eu"), "service.example.com"),
    (re.compile(r"netsynk\.eu"), "example.com"),
    (re.compile(r"\bWIN-SRV-\d+\b"), "DC01"),
    (re.compile(r"\bMS-?01\b"), "node-01"),
    (re.compile(r"(?i)\b(pve|nas|llm)-?(\d*)\.(?:lan|local)\b"), r"node\2.example.internal"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "user@example.com"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "00:00:00:00:00:00"),
]

# Si l'un de ces motifs survit, le fichier n'est pas écrit.
FORBIDDEN = [
    (re.compile(r"\b(?:10|127)\.\d+\.\d+\.\d+\b"), "IP privée"),
    (re.compile(r"\b192\.168\.\d+\.\d+\b"), "IP privée"),
    (re.compile(r"netsynk\.(eu|local)"), "domaine interne"),
    (re.compile(r"\b88\.96\.49\.57\b"), "IP publique du VPS"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY"), "clé privée"),
]

# Un secret en clair se détecte à part : `existingSecret: grafana-admin` est
# une référence à un objet Kubernetes, pas une valeur. On ne retient donc que
# les valeurs qui ne ressemblent pas à un nom de ressource.
SECRET_ASSIGN = re.compile(
    r"(?i)\b(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{12,})"
)
RESOURCE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")       # ex. grafana-admin
PLACEHOLDER = re.compile(r"(?i)^(change[_-]?me|x{4,}|<[^>]+>|\$\{.+\}|example.*)$")


def looks_like_secret(value):
    return not RESOURCE_NAME.match(value) and not PLACEHOLDER.match(value)

HEADER = {
    ".yaml": "# Extrait anonymisé d'une infrastructure réelle. Adresses et domaines\n"
             "# remplacés par des plages de documentation. Voir le README.\n\n",
    ".yml": "# Extrait anonymisé d'une infrastructure réelle. Adresses et domaines\n"
            "# remplacés par des plages de documentation. Voir le README.\n\n",
}


def sanitize(text):
    for pattern, replacement in RULES:
        text = pattern.sub(replacement, text)
    return text


def main():
    written, skipped, refused = 0, 0, 0

    for source, target in EXTRACTS.items():
        src = PRIVATE / source
        if not src.exists():
            print("· absent, ignoré : {}".format(source))
            skipped += 1
            continue

        clean = sanitize(src.read_text(encoding="utf-8"))

        problems = [label for pattern, label in FORBIDDEN if pattern.search(clean)]
        if any(looks_like_secret(v) for v in SECRET_ASSIGN.findall(clean)):
            problems.append("secret en clair")
        if problems:
            print("✗ REFUSÉ {} — {}".format(target, ", ".join(sorted(set(problems)))))
            refused += 1
            continue

        dest = HERE / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(HEADER.get(dest.suffix, "") + clean, encoding="utf-8")
        print("✓ {}".format(target))
        written += 1

    print("\n{} écrit(s), {} absent(s), {} refusé(s)".format(written, skipped, refused))
    if refused:
        sys.exit("des extraits contiennent encore des données sensibles")


if __name__ == "__main__":
    main()
