"""Test de fiabilité du tool calling d'un modèle Ollama (3 outils, plusieurs cas).

Usage :
    python test_tool_calling_v2.py LFM2.5
"""
import sys
import ollama

MODEL = sys.argv[1] if len(sys.argv) > 1 else "LFM2.5"
N_TRIALS = 5  # essais par cas

# Trois outils "bidons" : chacun est son PROPRE dictionnaire dans la liste.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a given city",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "Name of the city"},
                },
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two integers and return the sum",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer", "description": "First number"},
                    "b": {"type": "integer", "description": "Second number"},
                },
                "required": ["a", "b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_ticket",
            "description": "Create a support ticket with a title and a priority",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short title of the issue"},
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Priority of the ticket",
                    },
                },
                "required": ["title", "priority"],
            },
        },
    },
]

# Liste de cas : prompt, outil attendu (None = aucun outil), arguments attendus.
# A toi d'en ajouter (formulations vagues, autre langue, pièges...).
CASES = [
    {"id": "weather_1", "prompt": "What's the weather in Paris?",
     "tool": "get_weather", "args": {"city": "paris"}},
    {"id": "add_1", "prompt": "What is 17 plus 25?",
     "tool": "add", "args": {"a": "17", "b": "25"}},
    {"id": "ticket_1", "prompt": "Open a ticket titled 'Printer broken' with high priority.",
     "tool": "create_ticket", "args": {"title": "printer broken", "priority": "high"}},
    {"id": "none_1", "prompt": "Say hello to me.",
     "tool": None, "args": {}},
    {"id": "weather_2", "prompt": "What's the weather in Lyon?",
     "tool": "get_weather", "args": {"city": "lyon"}},
]


def norm(value):
    """Normalise une valeur pour la comparaison (le modèle peut renvoyer 17 ou '17')."""
    return str(value).strip().lower()


client = ollama.Client()
summary = []

for case in CASES:
    ok_tool = ok_args = errors = 0
    print(f"\n=== {case['id']} : {case['prompt']!r} (attendu : {case['tool']})")

    for i in range(1, N_TRIALS + 1):
        try:
            response = client.chat(
                model=MODEL,
                messages=[{"role": "user", "content": case["prompt"]}],
                tools=TOOLS,
                options={"temperature": 0.3},
            )
        except ollama.ResponseError as e:
            print(f"  [{i}] ERREUR : {e}")
            errors += 1
            continue

        calls = response.message.tool_calls or []

        if case["tool"] is None:
            # Cas négatif : le bon comportement est de NE PAS appeler d'outil.
            if not calls:
                ok_tool += 1
                ok_args += 1
                print(f"  [{i}] OK, pas d'outil appelé")
            else:
                print(f"  [{i}] KO, outil appelé à tort : {calls[0].function.name}")
            continue

        if not calls:
            print(f"  [{i}] KO, pas de tool call. Texte : {response.message.content[:60]!r}")
            continue

        name = calls[0].function.name
        args = calls[0].function.arguments
        good_tool = name == case["tool"]
        good_args = good_tool and all(
            norm(args.get(k)) == v for k, v in case["args"].items()
        )
        ok_tool += good_tool
        ok_args += good_args
        print(f"  [{i}] {'OK' if good_args else 'KO'}, {name}({args})")

    summary.append((case["id"], ok_tool, ok_args, errors))

print(f"\n===== RESUME ({MODEL}, {N_TRIALS} essais par cas) =====")
print(f"{'cas':<12} {'bon outil':<10} {'bons args':<10} {'erreurs'}")
for cid, t, a, e in summary:
    print(f"{cid:<12} {t}/{N_TRIALS:<8} {a}/{N_TRIALS:<8} {e}/{N_TRIALS}")