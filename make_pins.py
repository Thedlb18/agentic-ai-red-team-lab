"""Génère policy/tool_pins.json : l'empreinte (nom + description + schéma d'entrée)
des outils APPROUVÉS.

À lancer sur le serveur MCP PROPRE, après relecture humaine, puis à chaque fois
qu'un changement a été relu et approuvé :
    python make_pins.py          # affiche tout, demande confirmation
    python make_pins.py --yes    # sans confirmation (CI uniquement)
"""
import json
import sys

from agent.mcp_client import McpBridge, fingerprint, write_pins
from agent.tools import Context

with McpBridge(Context("medecin2", 2), "vulnerable", poison="none") as bridge:
    listed = bridge.list_tools()
    for t in listed:
        print(f"\n=== {t.name} ===\nDescription : {t.description}")
        print(f"Schéma      : {json.dumps(t.inputSchema, ensure_ascii=False, indent=2)}")
        print(f"Empreinte   : {fingerprint(t)}")
    if "--yes" not in sys.argv:
        if input("\nCes outils sont-ils sains et relus ? Écrire les empreintes ? [o/N] "
                 ).strip().lower() not in ("o", "oui", "y", "yes"):
            raise SystemExit("Abandon : aucune empreinte écrite.")
    pins = write_pins(listed)
print(f"\n{len(pins)} empreintes écrites dans policy/tool_pins.json")