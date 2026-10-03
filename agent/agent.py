"""Boucle de l'agent : modèle -> outil (via run_tool) -> résultat -> modèle.

Le modèle ne fait que PROPOSER des appels d'outils. Chaque appel passe par
run_tool(), qui applique (ou non, selon le mode) les contrôles du code.
"""
import json
import re

from agent.tools import ROOT, TOOL_SCHEMAS, Context, run_tool

MAX_STEPS = 6  # garde-fou : nombre maximum d'allers-retours avec le modèle


def load_system_prompt():
    """Extrait le texte du prompt depuis system_prompt.md (bloc ```text)."""
    text = (ROOT / "system_prompt.md").read_text(encoding="utf-8")
    match = re.search(r"## Prompt.*?```text\n(.*?)```", text, re.S)
    if match:
        return match.group(1).strip()
    print("[!] Bloc ```text introuvable dans system_prompt.md : "
          "le fichier entier est utilisé comme prompt.")
    return text.strip()


def build_system_message(ctx: Context):
    """Prompt + contexte FIABLE ajouté par le code (pas par l'utilisateur)."""
    return (
        load_system_prompt()
        + "\n\nCONTEXTE SYSTÈME (fourni par le système, fiable)\n"
        + f"Utilisateur authentifié : {ctx.user}\n"
        + f"Ticket en cours : {ctx.ticket_id}"
    )


def run_agent(ctx: Context, mode: str, user_message: str, model: str,
              client=None, temperature: float = 0.3):
    """Fait tourner l'agent. Renvoie (réponse_finale, trace)."""
    if client is None:
        import ollama
        client = ollama.Client()

    messages = [
        {"role": "system", "content": build_system_message(ctx)},
        {"role": "user", "content": user_message},
    ]
    trace = []  # un élément par appel d'outil proposé par le modèle

    for step in range(1, MAX_STEPS + 1):
        print(f"[étape {step}] appel du modèle (le premier appel peut être long)...",
              flush=True)
        response = client.chat(
            model=model,
            messages=messages,
            tools=TOOL_SCHEMAS,
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
            result = run_tool(name, args, ctx, mode)
            trace.append({"tool": name, "args": args, "result": result})
            print(f"    outil proposé : {name}({args}) -> "
                  f"{'OK' if result.get('ok') else 'REFUSÉ'}", flush=True)
            messages.append({
                "role": "tool",
                "tool_name": name,
                "content": json.dumps(result, ensure_ascii=False),
            })

    return "[arrêt : nombre maximum d'étapes atteint]", trace