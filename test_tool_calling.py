"""Test de fiabilité du tool calling d'un modèle Ollama.

Usage :
    python test_tool_calling.py granite3-dense:2b
"""
import sys
import ollama

MODEL = sys.argv[1] if len(sys.argv) > 1 else "LFM2.5"
N_TRIALS = 10
PROMPT = "What's the weather in Paris?"

# Déclaration de l'outil "bidon" (jamais exécuté dans ce test)
TOOLS = [{
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
}]

client = ollama.Client()
stats = {"tool_called": 0, "right_tool": 0, "right_arg": 0, "errors": 0}

for i in range(1, N_TRIALS + 1):
    try:
        response = client.chat(
            model=MODEL,
            messages=[{"role": "user", "content": PROMPT}],
            tools=TOOLS,
            options={"temperature": 0.3},  # un peu de variance pour voir la stabilité
        )
    except ollama.ResponseError as e:
        # ex. : le modèle ne supporte pas les tools
        print(f"[{i:02d}] ERREUR : {e}")
        stats["errors"] += 1
        continue

    calls = response.message.tool_calls or []
    if not calls:
        print(f"[{i:02d}] Pas de tool call. Texte : {response.message.content[:80]!r}")
        continue

    stats["tool_called"] += 1
    call = calls[0]
    name = call.function.name
    args = call.function.arguments  # dict
    print(f"[{i:02d}] Tool call : {name}({args})")

    if name == "get_weather":
        stats["right_tool"] += 1
        if str(args.get("city", "")).strip().lower() == "paris":
            stats["right_arg"] += 1

print(f"\nModèle : {MODEL}")
print(f"Tool appelé        : {stats['tool_called']}/{N_TRIALS}")
print(f"Bon outil          : {stats['right_tool']}/{N_TRIALS}")
print(f"Bon argument       : {stats['right_arg']}/{N_TRIALS}")
print(f"Erreurs API        : {stats['errors']}/{N_TRIALS}")