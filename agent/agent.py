"""Boucle de l'agent : modèle -> outil (via run_tool) -> résultat -> modèle.

Le modèle ne fait que PROPOSER des appels d'outils. Chaque appel passe par
run_tool(), qui applique (ou non, selon le mode) les contrôles du code.
"""
import json
import re

import agent.tools as tools_mod
from agent.tools import ROOT, TOOL_SCHEMAS, Context, audit, run_tool

MAX_STEPS = 6  # garde-fou : nombre maximum d'allers-retours avec le modèle


PROMPTS_DIR = ROOT / "prompts"


def available_prompts():
    """'full' (system_prompt.md) + tous les prompts/<nom>.txt."""
    names = sorted(p.stem for p in PROMPTS_DIR.glob("*.txt")) if PROMPTS_DIR.exists() else []
    return ["full"] + names


def load_system_prompt(name="full"):
    """'full' : texte du bloc ```text de system_prompt.md.
    autre nom : contenu de prompts/<nom>.txt (ex. 'minimal')."""
    if name != "full":
        return (PROMPTS_DIR / f"{name}.txt").read_text(encoding="utf-8").strip()
    text = (ROOT / "system_prompt.md").read_text(encoding="utf-8")
    match = re.search(r"## Prompt.*?```text\n(.*?)```", text, re.S)
    if match:
        return match.group(1).strip()
    print("[!] Bloc ```text introuvable dans system_prompt.md : "
          "le fichier entier est utilisé comme prompt.")
    return text.strip()


def build_system_message(ctx: Context, prompt_name="full"):
    """Prompt + contexte FIABLE ajouté par le code (pas par l'utilisateur)."""
    return (
        load_system_prompt(prompt_name)
        + "\n\nCONTEXTE SYSTÈME (fourni par le système, fiable)\n"
        + f"Utilisateur authentifié : {ctx.user}\n"
        + f"Ticket en cours : {ctx.ticket_id}"
    )


def _setup_mcp(ctx, mode, poison, quarantine):
    """Démarre le pont MCP et applique les défenses côté hôte.
    Renvoie (bridge, schémas montrés au modèle, outils en quarantaine, exécuteur)."""
    from agent.mcp_client import McpBridge, check_pins, sanitize_result, schemas_for_model

    bridge = McpBridge(ctx, mode, poison, tools_mod.RUN_ID)
    bridge.start()
    try:
        listed = bridge.list_tools()
        quarantined = frozenset()
        if mode == "hardened":
            alerts, bad = check_pins(listed)
            if alerts:
                for a in alerts:
                    audit(ctx, mode, "(mcp)", {}, "deny", a, layer="mcp-host")
            else:
                audit(ctx, mode, "(mcp)", {}, "allow", "empreintes conformes", layer="mcp-host")
            if quarantine:
                quarantined = frozenset(bad)

        def execute(name, args):
            result = bridge.call_tool(name, args)
            if mode == "hardened":
                result, dropped = sanitize_result(name, result)
                if dropped:
                    audit(ctx, mode, name, {}, "deny",
                          f"résultat filtré : {dropped}", layer="mcp-host")
            return result

        return bridge, schemas_for_model(listed, mode, TOOL_SCHEMAS, quarantined), quarantined, execute
    except BaseException:
        bridge.close()
        raise


def run_agent(ctx: Context, mode: str, user_message: str, model: str,
              client=None, temperature: float = 0.3, prompt_name: str = "full",
              use_mcp: bool = False, poison: str = "none", quarantine: bool = True):
    """Fait tourner l'agent. Renvoie (réponse_finale, trace).
    use_mcp : les outils s'exécutent via un serveur MCP (processus séparé).
    poison  : mode d'empoisonnement du serveur MCP ('none', 'description', 'output').
    quarantine : en mode durci, bloque les outils dont l'empreinte ne correspond pas."""
    if client is None:
        import ollama
        client = ollama.Client()

    bridge, tool_schemas, quarantined, executor = None, TOOL_SCHEMAS, frozenset(), None
    if use_mcp:
        bridge, tool_schemas, quarantined, executor = _setup_mcp(ctx, mode, poison, quarantine)
    try:
        return _loop(ctx, mode, user_message, model, client, temperature, prompt_name,
                     tool_schemas, quarantined, executor)
    finally:
        if bridge:
            bridge.close()


def _loop(ctx, mode, user_message, model, client, temperature, prompt_name,
          tool_schemas, quarantined, executor):
    messages = [
        {"role": "system", "content": build_system_message(ctx, prompt_name)},
        {"role": "user", "content": user_message},
    ]
    trace = []  # un élément par appel d'outil proposé par le modèle

    for step in range(1, MAX_STEPS + 1):
        print(f"[étape {step}] appel du modèle (le premier appel peut être long)...",
              flush=True)
        response = client.chat(
            model=model,
            messages=messages,
            tools=tool_schemas,
            options={"temperature": temperature},
        )
        msg = response.message
        messages.append(msg)

        calls = msg.tool_calls or []
        if not calls:
            return msg.content, trace  # le modèle répond en texte : fin

        for call in calls:
            name = call.function.name
            args = dict(call.function.arguments or {})
            # Les arguments viennent du modèle : NON FIABLES.
            if name in quarantined:  # fail closed : empreinte MCP non conforme
                audit(ctx, mode, name, args, "deny",
                      "outil en quarantaine (empreinte MCP non conforme)", layer="mcp-host")
                result = {"ok": False, "error": "Action refusée par la politique de sécurité."}
            else:
                result = run_tool(name, args, ctx, mode, executor=executor)
            trace.append({"tool": name, "args": args, "result": result})
            print(f"    outil proposé : {name}({args}) -> "
                  f"{'OK' if result.get('ok') else 'REFUSÉ'}", flush=True)
            messages.append({
                "role": "tool",
                "tool_name": name,
                "content": json.dumps(result, ensure_ascii=False),
            })

    return "[arrêt : nombre maximum d'étapes atteint]", trace