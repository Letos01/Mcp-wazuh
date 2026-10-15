# SPEC — mcp-wazuh

Servidor MCP (Model Context Protocol) **somente leitura** que expõe dados do Wazuh (alertas, agentes, regras, vulnerabilidades) para agentes de IA de forma padronizada, segura e auditável.

> Instrução para o Claude Code: implemente seguindo esta spec, fase por fase. Ao final de cada fase, rode os testes e só avance quando passarem. Antes de codar os clientes HTTP, confirme na documentação oficial do Wazuh (versão 4.x atual) os endpoints, os nomes de campos e o formato de autenticação. Não invente campos.

---

## 1. Objetivo e posicionamento

- Permitir que um LLM ou agente investigue incidentes no Wazuh por linguagem natural ("quais alertas de nível ≥ 10 no agente web-01 nas últimas 24h?", "quais técnicas MITRE mais apareceram esta semana?").
- Diferencial do projeto: **segurança do próprio servidor MCP**. Os dados dos alertas são conteúdo controlado pelo atacante (logs, URLs, payloads), então são tratados como entrada não confiável, com defesa contra prompt injection, limites, mínimo privilégio e trilha de auditoria.
- Projeto de portfólio público: código limpo, testes, README em inglês com diagrama, demo e seção de threat model.

## 2. Escopo

**Dentro do escopo**
- Somente leitura: consultas à Wazuh Server API e ao Wazuh Indexer.
- Transportes `stdio` (Claude Desktop / Claude Code) e `Streamable HTTP` (uso remoto, com autenticação).
- Auditoria, rate limiting, sanitização de saída, validação de entrada.

**Fora do escopo (documentar como trabalho futuro)**
- Qualquer escrita: active response, restart de agente, alteração de regras. Se um dia existir, só com aprovação humana explícita (human-in-the-loop) e uma flag separada.

## 3. Stack

- TypeScript (Node 22.12+), SDK oficial `@modelcontextprotocol/sdk`
- `zod` para schemas de entrada
- `undici` ou `fetch` nativo para HTTP; `pino` para logs
- `vitest` + `msw` (mock HTTP) para testes
- Docker + docker compose (servidor MCP + stack Wazuh single-node para demo)
- ESLint + Prettier; GitHub Actions rodando lint e testes

## 4. Arquitetura

```
Agente / Claude Desktop / Claude Code
        │  MCP (stdio | Streamable HTTP + Bearer)
        ▼
┌───────────────────────────── mcp-wazuh ─────────────────────────────┐
│ transport → auth (HTTP) → rate limit → zod validation → tool handler │
│                                     │                               │
│                          policy (limites, janela, campos)           │
│                                     │                               │
│        WazuhApiClient (JWT, 55000)      IndexerClient (OpenSearch)  │
│                                     │                               │
│        output sanitizer (untrusted wrapper) → audit log (JSONL)     │
└──────────────────────────────────────────────────────────────────────┘
        │                                   │
   Wazuh Server API                  Wazuh Indexer
   (agentes, regras, manager)        (wazuh-alerts-*, vulnerabilidades)
```

Estrutura de pastas:

```
src/
  index.ts              # bootstrap, escolhe transporte
  config.ts             # env + validação zod da config
  transports/{stdio,http}.ts
  security/{auth,rateLimit,sanitize,audit,policy}.ts
  clients/{wazuhApi,indexer}.ts
  tools/{searchAlerts,getAlert,alertStats,listAgents,getAgent,getRule,listVulnerabilities}.ts
  resources/managerInfo.ts
  prompts/triageAlert.ts
tests/
  unit/  integration/  injection/
specs/                  # esta spec e as próximas
docs/threat-model.md
docker-compose.yml
```

## 5. Configuração (variáveis de ambiente)

| Variável | Descrição |
|---|---|
| `WAZUH_API_URL` | ex.: `https://wazuh-manager:55000` |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | usuário com papel **somente leitura** |
| `WAZUH_INDEXER_URL` | ex.: `https://wazuh-indexer:9200` |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` | usuário com leitura apenas em `wazuh-alerts-*` e índices de vulnerabilidade |
| `TLS_CA_PATH` | CA para validar TLS; `TLS_INSECURE=false` por padrão (se `true`, logar aviso) |
| `MCP_TRANSPORT` | `stdio` ou `http` |
| `MCP_HTTP_PORT` | padrão 8080 |
| `MCP_AUTH_TOKENS` | lista de tokens Bearer aceitos (apenas no modo HTTP) |
| `MAX_RESULTS` | teto de resultados por chamada (padrão 50) |
| `MAX_TIME_WINDOW_DAYS` | janela máxima de consulta (padrão 30) |
| `AUDIT_LOG_PATH` | padrão `./audit/audit.jsonl` |

A config é validada no boot. Se faltar algo, o processo falha com mensagem clara. Nunca logar segredos.

## 6. Tools

Todas as tools são somente leitura, têm schema zod, respeitam `MAX_RESULTS` e `MAX_TIME_WINDOW_DAYS` e passam pelo sanitizador e pela auditoria. A descrição de cada tool deve ser clara para o LLM: o que faz, quando usar e limites.

| Tool | Entrada | Fonte | Saída |
|---|---|---|---|
| `search_alerts` | `time_from`, `time_to` (ISO 8601), `agent_id?`, `agent_name?`, `rule_level_min?` (0–15), `rule_id?`, `mitre_technique?` (ex.: T1059), `text?` (busca livre), `limit?` | Indexer | lista resumida: id, timestamp, agente, regra (id, nível, descrição), MITRE, trecho de log truncado |
| `get_alert` | `alert_id` | Indexer | alerta completo, com campos de log dentro do wrapper não confiável |
| `alert_stats` | `time_from`, `time_to`, `group_by` (`rule` \| `agent` \| `mitre_technique` \| `level`), `top?` | Indexer (aggregations) | contagens agregadas |
| `list_agents` | `status?` (active, disconnected, never_connected, pending), `os?`, `group?`, `limit?` | Server API | id, nome, IP, SO, status, versão, último keepalive |
| `get_agent` | `agent_id` | Server API | detalhes do agente |
| `get_rule` | `rule_id` | Server API | descrição, nível, grupos, MITRE, compliance |
| `list_vulnerabilities` | `agent_id?`, `severity?`, `limit?` | Indexer (índice de estado de vulnerabilidades, Wazuh 4.8+) | CVE, severidade, pacote, versão, agente |

**Resource:** `wazuh://manager/info` (versão e status do manager).

**Prompt:** `triage_alert(alert_id)`, um template que orienta o agente a buscar o alerta, a regra e o agente, correlacionar com alertas próximos no tempo e devolver classificação, técnica MITRE, severidade e próximos passos.

## 7. Requisitos de segurança (o coração do projeto)

1. **Mínimo privilégio:** documentar no README como criar o usuário e o papel somente leitura na Server API e no Indexer. O servidor não deve funcionar como admin. Se possível, detectar e avisar.
2. **Dados não confiáveis:** todo campo vindo de log (`full_log`, `data.*`, URLs, comandos) sai envolvido em:
   ```
   <untrusted_data source="wazuh_alert" id="...">
   ...conteúdo...
   </untrusted_data>
   ```
   As descrições das tools dizem explicitamente ao modelo que esse conteúdo é dado e nunca instrução.
3. **Sanitização:** remover caracteres de controle e sequências ANSI, neutralizar tentativas de fechar o wrapper (`</untrusted_data>` dentro do conteúdo), truncar campos longos (padrão 2.000 caracteres, com indicação `[truncated]`).
4. **Detecção de injeção:** heurística simples (padrões como "ignore previous instructions", "you are now", "system prompt", blocos que imitam tool calls). Quando detectar, adicionar `injection_suspected: true` no resultado e registrar na auditoria. Não bloquear, apenas sinalizar.
5. **Validação de entrada:** zod estrito; IDs com regex; janela de tempo limitada; nenhuma query DSL livre vinda do modelo. O servidor monta a query, e o campo `text` vira `simple_query_string` escapado.
6. **Limites:** rate limit por token ou sessão (ex.: 60 chamadas/min) e teto de resultados.
7. **Autenticação HTTP:** Bearer token obrigatório no modo HTTP, com comparação em tempo constante. Bind padrão em `127.0.0.1`.
8. **Auditoria:** uma linha JSONL por chamada com timestamp, sessão ou token (hash), tool, parâmetros, quantidade de resultados, duração, `injection_suspected` e erro. Sem segredos.
9. **TLS:** validar certificado por padrão.
10. **Erros:** mensagens genéricas para o modelo; detalhes só no log interno.

## 8. Testes e critérios de aceite

- **Unitários:** schemas, policy, sanitizador, detector de injeção e montagem das queries.
- **Integração (mock):** cada tool com respostas mockadas do Wazuh via `msw`, incluindo erro 401 com renovação do JWT, timeout e resultado vazio.
- **Suíte de injeção** (`tests/injection/`): pelo menos 8 alertas maliciosos (instrução direta, tentativa de fechar o wrapper, ANSI, payload em base64, imitação de tool call, texto em português). Critério: 100% saem dentro do wrapper, fechamentos neutralizados e `injection_suspected` marcado nos casos óbvios.
- **Integração real:** `docker compose up` sobe Wazuh single-node + mcp-wazuh. Um script gera alertas de exemplo (ex.: tentativas de SSH falhas) e um teste e2e chama `search_alerts`.
- **Cobertura:** ≥ 80% em `security/` e `tools/`.
- **Aceite final:** funciona no MCP Inspector e no Claude Desktop (config de exemplo no README); lint e testes verdes no GitHub Actions.

## 9. Fases de implementação

1. Bootstrap: projeto TS, config com zod, transporte stdio, uma tool `get_rule` ponta a ponta com teste.
2. Clientes: `WazuhApiClient` (JWT com renovação) e `IndexerClient`, com testes mockados.
3. Tools restantes, resource e prompt.
4. Camada de segurança: sanitizador, detector, auditoria, rate limit e suíte de injeção.
5. Transporte HTTP com autenticação Bearer.
6. Docker compose com Wazuh e teste e2e.
7. Documentação: README (inglês), `docs/threat-model.md` (ameaças: prompt injection via logs, credencial vazada, exfiltração via agente, abuso de consulta; mitigação de cada uma) e GIF da demo.

## 10. README — seções obrigatórias

Pitch em uma frase · diagrama de arquitetura · lista de tools · quick start (docker compose) · configuração no Claude Desktop e no Claude Code · criação de usuários somente leitura no Wazuh · modelo de segurança e resumo do threat model · GIF da demo (Claude investigando um alerta) · roadmap (integração com `soc-agents`, tools de escrita com human-in-the-loop) · licença MIT.
