# agentic-ai-red-team-lab

1ère partie du projet:
J'ai téléchargé ollama et j'ai ensuite fais des recherches sur le bon modèle qui nous permettra de réussir le projet. Un des critères du choix de notre modèle a été qu'il peut utiliser tools car forcément on en aura besoin que ce soit pour créer des tickets, lire des documents etc... J'ai testé deux modeles qui sont justement disponibles sur ollama, un d'eux est granite3-dense mais lorsque j'ai fais les tests pour voir si il récupère bien la tool enoncé j'ai remarqué que non et que cela a échoué. J'ai ensuite testé un deuxième modèle LFM2.5 et j'ai fais un premier test avec juste la fonction get_weather() comme le premier modèle et la ca a marché, j'ai modifié le fichier de test et j'ai rajouté d'autres fonctions telles que add, create_ticket, une fonction qui justement ne prend pas de fonction qui renvoie juste hello et enfin un deuxième get_weather pour une autre ville qu'est Lyon mais je voulais la météo de demain. Pour cette fonction la, le modèle n'a pas su répondre car j'avais programmé le temps que pour aujourd'hui et comme j'ai mis demain en question, le modèle n'a pas su répondre ce qui est une bonne nouvelle à cela. Mais pour être sur que le modèle marche bien j'ai changé la question et je l'ai mis pour aujourd'hui et ca nous a donné des bons résultats comme on l'attendait. Il y a une preuve de mes résultats qui est une capture d'écran "Test_modèle.png".

## Installation et lancement

Depuis la racine du dépôt, installe les dépendances dans l'environnement virtuel :

```sh
make install
make setup
make run-agent
```

`make run-agent` lance l'agent en mode durci sur le ticket 2 de `medecin2`, avec
le modèle `LFM2.5` par défaut. Ollama doit être installé et ce modèle disponible
localement. Pour lancer le mode vulnérable à des fins de comparaison, utilise
`make run-agent-vulnerable`. Les commandes de test et de campagne sont
détaillées dans [PLAN_DE_TESTS.md](./PLAN_DE_TESTS.md).

## Commandes de test

`make help` affiche les cibles disponibles. Voici à quoi servent les principales :

| Commande | Rôle |
|---|---|
| `make test-catalog` | Vérifie le catalogue d'attaques et les comportements simulés des modes vulnérable/durci, sans appeler Ollama. |
| `make test-gateway` | Vérifie directement les règles de sécurité : identité, permissions, chemins, arguments, secrets, quotas et révocation. |
| `make test-mcp` | Lance les tests d'intégration MCP avec un faux modèle : empoisonnement, empreintes, quarantaine et filtrage des résultats. |
| `make test-tool-calling` | Vérifie avec Ollama que LFM2.5 choisit les bons outils et arguments sur des exemples simples. |
| `make test-batch-scripted` | Joue le catalogue complet avec un modèle scripté en modes vulnérable et durci, y compris les cas MCP; pas d'appel LLM. |
| `make test-batch-ollama` | Campagne complète avec le vrai modèle Ollama; plus lente et probabiliste. |
| `make test-batch` | Campagne paramétrable via `N`, `MODEL`, `MODE`, `FAMILIES`, `CASES`, `PROMPTS` et `MCP`. |
| `make demo-defense-boundary` | Montre sur l'attaque indirecte `IND-01` qu'un modèle qui obéit peut réussir en mode vulnérable, tandis que la gateway bloque l'accès dangereux en mode durci; sans Ollama. |
| `make test-all` | Lance les tests déterministes locaux, MCP, puis la campagne scriptée complète; n'a pas besoin d'Ollama. |

Les tests et campagnes réinitialisent des données fictives et laissent des
rapports dans `benchmarks/`. Pour les détails, les prérequis et les exemples de
campagnes ciblées, voir [PLAN_DE_TESTS.md](./PLAN_DE_TESTS.md).

### Ce que la défense garantit — et ne garantit pas

Le system prompt demande au modèle de traiter les pièces jointes comme des
données non fiables, mais cette consigne n'est pas une barrière de sécurité :
le modèle peut la suivre ou s'en écarter. La séparation importante est entre
**proposition** et **exécution** : en mode durci, chaque appel d'outil proposé
est soumis à la Policy Gateway dans le code avant toute exécution. La gateway
vérifie notamment les droits, le périmètre du fichier, les arguments, les
motifs sensibles, les quotas et les approbations.

Lancer `make demo-defense-boundary` pour voir un scénario contrôlé. Le modèle
scripté obéit intentionnellement à l'injection : ce n'est pas une mesure de
résistance d'un LLM, mais une démonstration que le contrôle technique bloque
l'action interdite indépendamment de l'obéissance du modèle.

Cette défense reste limitée au périmètre implémenté et testé : elle ne prouve
pas la sécurité face à toutes les attaques ou à un modèle arbitraire. Elle ne
protège pas contre la compromission de l'hôte ou des fichiers de policy, et le
filtrage des appels d'outils ne garantit pas à lui seul que chaque réponse en
texte libre est sûre. Les familles `SO` restent notamment un risque résiduel.
Les limites et les résultats à mesurer sont détaillés dans
[threat_model.md](./threat_model.md).