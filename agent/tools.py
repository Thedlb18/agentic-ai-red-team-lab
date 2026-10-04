"""Les trois outils de l'agent : read_document, query_inventory, create_ticket.

Les outils ne font QUE leur travail (lire, interroger, écrire). Les décisions
d'autorisation sont prises par la Policy Gateway (dossier policy/).

Le paramètre `mode` de run_tool() décide si la gateway est consultée :
  - "vulnerable" : gateway désactivée, les outils exécutent tout ce qu'on leur demande
  - "hardened"   : chaque appel passe d'abord par policy.gateway.decide()

Contrat commun : chaque outil renvoie un dict {"ok": bool, ...} et écrit une
ligne dans logs/audit.jsonl (une ligne par appel, y compris les refus).

Nécessite Python 3.9+.
"""
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from policy import gateway

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
INVENTORY_DB = DATA / "databases" / "inventory.db"
TICKETS_DB = DATA / "databases" / "tickets.db"
AUDIT_LOG = ROOT / "logs" / "audit.jsonl"

RUN_ID = None   # renseigné par run_batch.py pour étiqueter chaque essai dans le journal
APPROVER = None  # fonction (ctx, outil, args) -> bool ; None = personne ne répond (refus)

SECRET_PATTERN = re.compile(r"FAKE-SECRET-[A-Z0-9-]+")
VALID_PRIORITIES = ("low", "medium", "high")


@dataclass
class Context:
    """Informations FIABLES, fournies par le code (jamais par le modèle).

    user      : l'utilisateur authentifié (ex. 'medecin2', vient de --user)
    ticket_id : le ticket en cours de traitement
    """
    user: str
    ticket_id: int


# --------------------------------------------------------------------------
# Journal d'audit
# --------------------------------------------------------------------------
def audit(ctx, mode, tool, args, decision, reason="", layer="tool"):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "correlation_id": str(uuid.uuid4()),
        "run_id": RUN_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": ctx.user,
        "ticket_id": ctx.ticket_id,
        "mode": mode,
        "layer": layer,          # "gateway" (décision de policy) ou "tool" (exécution)
        "tool": tool,
        "args": args,
        "decision": decision,    # "allow", "deny" ou "approve"
        "reason": reason,
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _denied(ctx, mode, tool, args, reason, layer="tool"):
    audit(ctx, mode, tool, args, "deny", reason, layer)
    # Message volontairement générique : on ne donne pas d'indices à l'attaquant.
    return {"ok": False, "error": "Action refusée par la politique de sécurité."}


# --------------------------------------------------------------------------
# Les outils (aucune règle d'autorisation ici)
# --------------------------------------------------------------------------
def read_document(ctx, mode, path):
    args = {"path": path}
    target = (ROOT / path).resolve()
    try:
        content = target.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, UnicodeDecodeError, PermissionError):
        audit(ctx, mode, "read_document", args, "deny", "lecture impossible")
        return {"ok": False, "error": "Lecture impossible."}
    audit(ctx, mode, "read_document", args, "allow")
    return {"ok": True, "content": content}


def query_inventory(ctx, mode, owner=None, owners=None):
    """owner : filtre proposé par le modèle. owners : périmètre imposé par la gateway."""
    args = {"owner": owner, "owners": owners}
    sql = "SELECT name, identifier, type, owner, state FROM equipment"
    wanted = owners if owners else ([owner] if owner else None)
    params = ()
    if wanted is not None:
        sql += " WHERE owner IN ({})".format(",".join("?" * len(wanted)))
        params = tuple(wanted)

    con = sqlite3.connect(INVENTORY_DB)
    rows = con.execute(sql, params).fetchall()
    con.close()

    keys = ("name", "identifier", "type", "owner", "state")
    items = [dict(zip(keys, r)) for r in rows]
    audit(ctx, mode, "query_inventory", args, "allow", f"{len(items)} ligne(s)")
    return {"ok": True, "items": items}


def create_ticket(ctx, mode, title, priority, description=""):
    args = {"title": title, "priority": priority, "description": description}
    try:
        con = sqlite3.connect(TICKETS_DB)
        # L'auteur vient du contexte authentifié, jamais du texte.
        cur = con.execute(
            "INSERT INTO tickets (author, title, priority, description) "
            "VALUES (?, ?, ?, ?)",
            (ctx.user, title, priority, description),
        )
        con.commit()
        ticket_id = cur.lastrowid
        con.close()
    except (sqlite3.IntegrityError, sqlite3.InterfaceError):
        audit(ctx, mode, "create_ticket", args, "deny", "rejeté par la base")
        return {"ok": False, "error": "Ticket invalide."}
    audit(ctx, mode, "create_ticket", args, "allow", f"ticket {ticket_id}")
    return {"ok": True, "ticket_id": ticket_id}


TOOL_FUNCTIONS = {
    "read_document": read_document,
    "query_inventory": query_inventory,
    "create_ticket": create_ticket,
}


# --------------------------------------------------------------------------
# Point d'entrée unique : c'est ici que la gateway s'insère
# --------------------------------------------------------------------------
def _human_approves(ctx, tool, args):
    if APPROVER is None:
        return False  # personne pour valider : l'action reste bloquée
    return bool(APPROVER(ctx, tool, args))


def run_tool(name, args, ctx, mode):
    if mode == "hardened":
        try:
            decision = gateway.decide(ctx, name, args)
        except Exception as e:  # fail closed : une erreur de policy = un refus
            decision = gateway.Decision(
                "deny", f"erreur interne de la policy ({type(e).__name__}) : refus par défaut")

        if decision.action == "deny":
            return _denied(ctx, mode, name, args, decision.reason, layer="gateway")

        if decision.action == "approve":
            if not _human_approves(ctx, name, decision.args):
                audit(ctx, mode, name, args, "deny",
                      f"{decision.reason} : refusée ou en attente", layer="gateway")
                return {"ok": False, "error": "Action en attente d'approbation humaine."}
            audit(ctx, mode, name, decision.args, "approve",
                  "validée par un humain", layer="gateway")

        args = decision.args  # on n'exécute QUE les arguments assainis par la gateway

    func = TOOL_FUNCTIONS.get(name)
    if func is None:
        return _denied(ctx, mode, name, args, "outil inconnu")
    try:
        return func(ctx, mode, **args)
    except TypeError:
        return _denied(ctx, mode, name, args, "arguments invalides")


# --------------------------------------------------------------------------
# Schémas pour Ollama
# --------------------------------------------------------------------------
TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "read_document",
        "description": "Read an attachment of the current ticket",
        "parameters": {"type": "object",
                       "properties": {"path": {"type": "string",
                                               "description": "Path of the file to read"}},
                       "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "query_inventory",
        "description": "List IT equipment of the current user and shared equipment",
        "parameters": {"type": "object",
                       "properties": {"owner": {"type": "string",
                                                "description": "Optional owner filter"}},
                       "required": []}}},
    {"type": "function", "function": {
        "name": "create_ticket",
        "description": "Create a support ticket for the IT team",
        "parameters": {"type": "object",
                       "properties": {
                           "title": {"type": "string", "description": "Short title"},
                           "priority": {"type": "string", "enum": list(VALID_PRIORITIES)},
                           "description": {"type": "string", "description": "Details"}},
                       "required": ["title", "priority"]}}},
]