"""Policy Gateway : décide si une action PROPOSÉE par le modèle peut s'exécuter.

Le modèle ne fait que demander. Cette fonction (du code, pas du texte) répond :
  - "allow"   : l'action peut s'exécuter (avec les arguments assainis)
  - "deny"    : refusée
  - "approve" : action à fort impact, un humain doit valider

Ordre des contrôles (celui du PDF) :
  1. identité  2. allowlist d'outils (+ quota par run)  3. forme des arguments
  4. motifs interdits  5. périmètre (ressource) et validation  6. niveau d'impact

Principe : en cas de doute ou d'erreur, on REFUSE (fail closed).
Les règles sont dans rules.json ; la révocation (kill switch) dans revoked.json.
"""
import base64
import codecs
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

POLICY_DIR = Path(__file__).resolve().parent
ROOT = POLICY_DIR.parent
DATA = ROOT / "data"
TICKETS_DB = DATA / "databases" / "tickets.db"
RULES_FILE = POLICY_DIR / "rules.json"
REVOKED_FILE = POLICY_DIR / "revoked.json"


@dataclass
class Decision:
    action: str                      # "allow" | "deny" | "approve"
    reason: str = ""                 # raison précise (journal uniquement, jamais montrée au modèle)
    args: dict = field(default_factory=dict)  # arguments ASSAINIS à utiliser pour l'exécution


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _deny(reason):
    return Decision("deny", reason)


# --------------------------------------------------------------------------
# Détection de motifs interdits, y compris ENCODÉS (base64, hex, ROT13, inversé,
# caractères invisibles). Un filtre regex seul est contourné par un simple encodage.
# --------------------------------------------------------------------------
_INVISIBLE = re.compile(r"[\s\u200b-\u200f\u2060\ufeff]+")


def _strings(obj, depth=0):
    if depth > 5:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v, depth + 1)
    elif obj is not None:
        yield str(obj)


def _text_variants(args):
    yield json.dumps(args, ensure_ascii=False, default=str)  # forme brute (comme avant)
    for text in _strings(args):
        text = text[:20000]
        yield text
        yield text.upper()
        yield text[::-1]
        yield codecs.decode(text, "rot13")
        yield _INVISIBLE.sub("", text)
        for tok in re.findall(r"[A-Za-z0-9+/=_\-]{16,}", text)[:30]:
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    yield decoder(tok + "=" * (-len(tok) % 4)).decode("utf-8", "ignore")
                except Exception:  # noqa: BLE001
                    pass
        for tok in re.findall(r"[0-9a-fA-F]{16,}", text)[:30]:
            try:
                yield bytes.fromhex(tok[: len(tok) // 2 * 2]).decode("utf-8", "ignore")
            except ValueError:
                pass


# --------------------------------------------------------------------------
# Contrôles propres à chaque outil (périmètre + validation)
# Chacun renvoie soit une Decision "deny", soit le dict d'arguments assainis.
# --------------------------------------------------------------------------
def _check_read_document(ctx, args, cfg, rules):
    path = args["path"]
    if (not isinstance(path, str) or not path or "\x00" in path
            or len(path) > cfg["max_path_len"]):
        return _deny("chemin invalide")

    # On juge le chemin RÉEL (après suppression des '..' et des raccourcis).
    target = (ROOT / path).resolve()

    con = sqlite3.connect(TICKETS_DB)
    row = con.execute("SELECT author, attachment_dir FROM tickets WHERE id = ?",
                      (ctx.ticket_id,)).fetchone()
    con.close()
    if row is None:
        return _deny("ticket inconnu")
    author, attachment_dir = row
    if author != ctx.user:
        return _deny("le ticket n'appartient pas à l'utilisateur authentifié")
    if not attachment_dir:
        return _deny("ce ticket n'a pas de pièce jointe")

    allowed_dir = (DATA / attachment_dir).resolve()
    if not target.is_relative_to(allowed_dir):
        return _deny("chemin hors du dossier de pièces jointes du ticket")
    if not target.is_file():
        return _deny("fichier introuvable")
    return {"path": str(target)}  # on exécute exactement ce qui a été vérifié


def _check_query_inventory(ctx, args, cfg, rules):
    owner = args.get("owner")
    allowed = [ctx.user] + list(rules["shared_owners"])
    if owner is not None:
        if not isinstance(owner, str) or owner not in allowed:
            return _deny(f"propriétaire hors périmètre : {owner}")
        return {"owners": [owner]}
    # Aucun filtre demandé : la gateway IMPOSE le périmètre de l'utilisateur.
    return {"owners": allowed}


def _check_create_ticket(ctx, args, cfg, rules):
    title = args["title"]
    priority = args["priority"]
    description = args.get("description", "")
    if not isinstance(title, str) or not (1 <= len(title) <= cfg["max_title_len"]):
        return _deny("titre invalide")
    if not isinstance(priority, str) or priority not in cfg["allowed_priorities"]:
        return _deny("priorité invalide")
    if not isinstance(description, str) or len(description) > cfg["max_description_len"]:
        return _deny("description invalide")
    return {"title": title, "priority": priority, "description": description}


CHECKERS = {
    "read_document": _check_read_document,
    "query_inventory": _check_query_inventory,
    "create_ticket": _check_create_ticket,
}


# --------------------------------------------------------------------------
# Décision
# --------------------------------------------------------------------------
def decide(ctx, tool, args):
    rules = _load(RULES_FILE)
    revoked = _load(REVOKED_FILE)

    # 1. Identité (fournie par le code, jamais par le texte)
    if not isinstance(ctx.user, str) or not ctx.user:
        return _deny("identité absente")
    if ctx.user in revoked.get("users", []):
        return _deny("identité révoquée")

    # 2. Allowlist d'outils
    if tool not in rules["task_allowlist"] or tool not in rules["tools"]:
        return _deny(f"outil hors allowlist : {tool}")
    if tool in revoked.get("tools", []):
        return _deny(f"outil révoqué : {tool}")
    cfg = rules["tools"][tool]

    # 2bis. Quota d'appels par run (excessive agency : tickets en masse, boucles d'outils)
    limit = rules.get("max_calls_per_run", {}).get(tool)
    if limit is not None and getattr(ctx, "counts", {}).get(tool, 0) >= limit:
        return _deny(f"quota d'appels atteint pour {tool} ({limit} par run)")

    # 3. Forme des arguments
    if not isinstance(args, dict):
        return _deny("arguments invalides")
    extra = set(args) - set(cfg["args"])
    if extra:
        return _deny(f"arguments inattendus : {sorted(extra)}")
    missing = [a for a in cfg.get("required_args", []) if a not in args]
    if missing:
        return _deny(f"arguments manquants : {missing}")

    # 4. Motifs interdits (ex. le secret) dans n'importe quel argument, même encodé
    for variant in _text_variants(args):
        for pattern in rules["forbidden_text_patterns"]:
            if re.search(pattern, variant):
                return _deny("motif sensible détecté dans les arguments (éventuellement encodé)")

    # 5. Périmètre de la ressource + validation propres à l'outil
    result = CHECKERS[tool](ctx, args, cfg, rules)
    if isinstance(result, Decision):
        return result
    safe_args = result

    # 6. Niveau d'impact -> approbation humaine si nécessaire
    impact = cfg["impact"]
    if safe_args.get("priority") in cfg.get("high_impact_priorities", []):
        impact = "high"
    if impact in rules["approval_required_for_impact"]:
        return Decision("approve", f"impact {impact} : approbation humaine requise", safe_args)

    return Decision("allow", "", safe_args)


# --------------------------------------------------------------------------
# Révocation (kill switch) : effet immédiat, sans redémarrer quoi que ce soit
# --------------------------------------------------------------------------
def _update_revoked(kind, name, add):
    data = _load(REVOKED_FILE)
    items = set(data.get(kind, []))
    (items.add if add else items.discard)(name)
    data[kind] = sorted(items)
    REVOKED_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def revoke(kind, name):
    """kind : 'users' ou 'tools'."""
    _update_revoked(kind, name, add=True)


def restore(kind, name):
    _update_revoked(kind, name, add=False)