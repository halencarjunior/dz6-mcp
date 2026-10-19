# dz6-mcp

<p align="center">
  <img src="DZ6MCP.png" alt="Logotipo do dz6-mcp" width="720">
</p>

[![Licença: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![MCP: stdio](https://img.shields.io/badge/MCP-stdio-6f42c1.svg)](https://modelcontextprotocol.io/)

[English](README.md) | **Português (Brasil)**

Um servidor [Model Context Protocol](https://modelcontextprotocol.io/) que disponibiliza o editor hexadecimal de terminal [dz6](https://dz6.dev.br) para qualquer cliente compatível com MCP.

O `dz6-mcp` se comunica por MCP via **stdio** e utiliza o próprio dz6 como mecanismo de execução. Assim, oferece o mesmo acesso a arquivos com mmap, o mesmo analisador PE/ELF (goblin), a mesma sintaxe de busca e o mesmo modelo de anotações, sem precisar de uma interface de terminal.

- **Inspeção**: metadados, bytes, inteiros, strings, entropia, dumps hexadecimais, cabeçalhos PE/ELF, seções, segmentos, símbolos, importações/exportações, notas e diretórios.
- **Busca**: texto e bytes hexadecimais literais, curingas do dz6 e um mecanismo de assinaturas com curingas de nibble, intervalos de bytes arbitrários, alternativas, máscaras e conjuntos de padrões nomeados.
- **Conversão**: endereços VA/RVA de PE e endereços virtuais de ELF para offsets de arquivo e vice-versa.
- **Edição**: alterações de bytes mantidas em memória, preenchimento, desfazer, salvamento e truncamento.
- **Anotações**: comentários, marcadores e blocos coloridos, persistidos no arquivo auxiliar TOML `<file>.dz6` do dz6.
- **Diagnóstico**: metadados do servidor, nível de log ajustável durante a execução e histórico de logs em memória.

Nada é gravado no arquivo analisado até a chamada de `save`, com a única exceção de `truncate`, que é explicitamente destrutivo.

## Sumário

- [Como funciona](#como-funciona)
- [Início rápido](#início-rápido)
- [Requisitos](#requisitos)
- [Compilação e instalação](#compilação-e-instalação)
- [Opções de linha de comando](#opções-de-linha-de-comando)
- [Configuração dos clientes](#configuração-dos-clientes)
- [Conceitos fundamentais](#conceitos-fundamentais)
- [Referência das ferramentas](#referência-das-ferramentas)
  - [Arquivos](#arquivos)
  - [Leitura e análise](#leitura-e-análise)
  - [Inspeção de binários](#inspeção-de-binários)
  - [Edição](#edição)
  - [Anotações](#anotações)
  - [Diagnóstico](#diagnóstico)
- [Sintaxe de busca](#sintaxe-de-busca)
- [Varredura de padrões](#varredura-de-padrões)
- [Referência PE/ELF](#referência-peelf)
- [Fluxos de trabalho](#fluxos-de-trabalho)
- [Arquitetura](#arquitetura)
- [Solução de problemas](#solução-de-problemas)
- [Segurança](#segurança)
- [Perguntas frequentes](#perguntas-frequentes)
- [Licença](#licença)

## Como funciona

```text
Cliente MCP (Claude, Codex, OpenCode, …)
        │  JSON-RPC 2.0 via stdio
        ▼
dz6-mcp ── estado: uma App do dz6 por arquivo aberto
        │            ├─ mmap do arquivo
        │            ├─ alterações pendentes (em memória)
        │            └─ comentários / marcadores / blocos
        ▼
arquivo no disco             arquivo auxiliar <file>.dz6
```

- stdout transporta **somente** JSON-RPC. Logs e mensagens de inicialização são enviados para stderr.
- Os arquivos são abertos **sob demanda** por qualquer ferramenta que aceite `path` e permanecem em cache durante a sessão.
- Leituras, buscas e análises usam os **bytes efetivos**: os bytes mapeados por mmap com as alterações pendentes aplicadas sobre eles.
- A análise estrutural (`headers`, `sections`, `symbols`, `pe_info`, `elf_info`) lê o mapeamento do arquivo no disco e, portanto, reflete o conteúdo salvo.
- `save` grava as alterações pendentes e o arquivo auxiliar de anotações.

## Início rápido

```sh
# 1. Prepare a dependência dz6 com o patch (veja Requisitos) e compile
cargo build --release --locked

# 2. Configure o cliente MCP com o caminho absoluto do executável
#    /absolute/path/to/dz6-mcp/target/release/dz6-mcp

# 3. Use no cliente, por exemplo:
#    "Use o dz6 para abrir /bin/true, listar suas seções e mostrar o interpretador."
```

Configuração mínima de um cliente:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/absolute/path/to/dz6-mcp/target/release/dz6-mcp",
      "args": ["--readonly"]
    }
  }
}
```

Remova `--readonly` quando o cliente precisar preparar e salvar alterações.

## Requisitos

- Rust 1.89 ou mais recente, devido à edição 2024 e aos requisitos das dependências fixadas. Validado localmente com Rust 1.99.1.
- Um checkout do dz6 que exponha um **alvo de biblioteca**. O dz6 original é distribuído como executável, então esse checkout precisa fornecer:

  1. `src/lib.rs` exportando os módulos do dz6 (`pub mod app; pub mod hex; …`), além da macro `beep!` e de `update_page_size`.
  2. `src/main.rs` consumindo a biblioteca em vez de declarar os módulos.
  3. `beep!` emitindo o sinal sonoro do terminal em **stderr** (`eprint!`), para reservar stdout ao protocolo MCP.

Essas mudanças preservam a compatibilidade do código com a interface de terminal (TUI). O servidor depende do dz6 por meio de um caminho local:

```toml
dz6 = { path = "../dz6" }
```

Este repositório inclui as mudanças necessárias em [`patches/dz6-library.patch`](patches/dz6-library.patch). No diretório em que deseja manter os dois checkouts, execute:

```sh
git clone https://github.com/halencarjunior/dz6-mcp.git
git clone https://github.com/mentebinaria/dz6.git
git -C dz6 checkout --detach 9612897db2b0c5ec75ea92285b183e1062ba9af9
git -C dz6 apply --check ../dz6-mcp/patches/dz6-library.patch
git -C dz6 apply ../dz6-mcp/patches/dz6-library.patch
cd dz6-mcp
cargo build --release --locked
```

Use um checkout novo do dz6 para esses comandos. O patch depende exatamente do commit indicado: adiciona o alvo de biblioteca, adapta o ponto de entrada da TUI e direciona o sinal sonoro para stderr. Não é necessário publicar mudanças no dz6 separadamente.

A instalação com `cargo install --git` ou pelo crates.io não é suportada enquanto o servidor depender desse diretório vizinho.

Para validar mudanças antes de enviá-las:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

## Compilação e instalação

```sh
cargo build --release
# executável: target/release/dz6-mcp
```

Instale em um diretório presente no `PATH`:

```sh
cargo install --path .
# ou
install -m 0755 target/release/dz6-mcp ~/.local/bin/dz6-mcp
```

Verifique a compilação sem usar um cliente:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"example","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./target/release/dz6-mcp 2>/dev/null
```

A última resposta deve anunciar 39 ferramentas.

## Opções de linha de comando

```text
dz6-mcp [OPTIONS]

  --readonly               Abre arquivos por padrão em modo somente leitura
  -v, --verbose...         Aumenta a verbosidade: -v info, -vv debug, -vvv trace
      --log-level FILTER   Diretiva EnvFilter (sobrescreve -v e RUST_LOG)
      --log-file PATH      Também acrescenta logs ao arquivo PATH
  -h, --help               Exibe a ajuda
  -V, --version            Exibe a versão
```

Precedência do filtro: `--log-level` > `RUST_LOG` > `-v` > padrão `warn`.
`--log-level` aceita um nível (`trace`, `debug`, `info`, `warn`, `error`, `off`) ou uma lista de diretivas, como `dz6_mcp=debug,rmcp=info`.

Na inicialização, stderr mostra mensagens como estas, em inglês:

```text
dz6-mcp 0.1.0 (pid 12345) — stdio transport, read-write mode
log level: warn (change with --log-level, RUST_LOG or the log_level tool); log file: none
```

Os logs de cada chamada, com nome da ferramenta, duração em milissegundos e indicação de erro, são emitidos no nível `info`. As últimas 2000 linhas ficam em memória e podem ser consultadas com `logs_tail`, pois a maioria dos clientes MCP não exibe o stderr do servidor.

## Configuração dos clientes

Todos os clientes abaixo executam `dz6-mcp` como um servidor local via **stdio**. O requisito comum é o caminho absoluto do executável:

```sh
cargo build --release
# /absolute/path/to/dz6-mcp/target/release/dz6-mcp
```

Adicione `--readonly` aos argumentos para abrir arquivos por padrão em modo somente leitura. As ferramentas também anunciam indicações MCP de somente leitura, permitindo que clientes com um sistema de aprovação autorizem leituras automaticamente e solicitem aprovação antes de edições. `truncate` também anuncia `destructive_hint`.

> **Importante:** `command` deve apontar para o **executável**, não para um diretório. Usar `.../target/release` é a causa mais comum de erros de servidor não conectado.

| Cliente | Configuração |
| --- | --- |
| [Claude Desktop](#claude-desktop) | `claude_desktop_config.json` |
| [Claude Code](#claude-code) | `claude mcp add`, `.mcp.json` ou `~/.claude.json` |
| [OpenAI Codex](#openai-codex) | `~/.codex/config.toml` (`[mcp_servers.dz6]`) |
| [DeepSeek Harness (dsh)](#deepseek-harness-dsh) | `$DSH_HOME/profiles/<profile>/cordis.patch.yml` |
| [OpenCode](#opencode) | `opencode.jsonc` (`mcp.servers`) |
| [Kilo Code](#kilo-code) | `kilo.jsonc` (`mcp`), ou o antigo `mcp_settings.json` |
| [Pi](#pi) | `~/.pi/agent/mcp.json` ou `.pi/mcp.json` (`mcpServers`) |
| [Cursor / VS Code](#cursor--vs-code--clientes-genéricos) | Configurações MCP do cliente |
| [stdio direto](#stdio-direto) | Inicie o processo e troque mensagens JSON-RPC |

Após editar a configuração, reinicie o cliente ou recarregue suas conexões MCP. As listas de ferramentas normalmente ficam em cache por sessão; novas ferramentas de um servidor recompilado só aparecem após a reconexão.

### Claude Desktop

Adicione o servidor ao arquivo `claude_desktop_config.json` e reinicie o aplicativo:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

### Claude Code

A CLI grava a configuração para você:

```sh
claude mcp add dz6 -- /path/to/dz6-mcp                 # escopo local (padrão)
claude mcp add --scope user dz6 -- /path/to/dz6-mcp    # todos os projetos
claude mcp add --scope project dz6 -- /path/to/dz6-mcp # compartilhado via .mcp.json
claude mcp list
claude mcp get dz6
```

Ou edite diretamente `.mcp.json` na raiz do projeto (escopo de projeto, destinado ao versionamento), ou a chave `mcpServers` no nível superior de `~/.claude.json` (escopo de usuário):

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

Execute `/mcp` dentro da sessão para verificar a conexão e aprovar servidores configurados no escopo do projeto.

### OpenAI Codex

O Codex lê `~/.codex/config.toml` ou `.codex/config.toml` em projetos confiáveis. Adicione o servidor pela CLI:

```sh
codex mcp add dz6 -- /path/to/dz6-mcp
codex mcp list
codex mcp get dz6
```

Ou diretamente em `config.toml`:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
args = []
startup_timeout_sec = 10
tool_timeout_sec = 60
```

Para uma sessão com abertura padrão em modo somente leitura:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
args = ["--readonly"]
```

Como as ferramentas anunciam indicações de somente leitura, o Codex pode aprovar leituras automaticamente e perguntar antes de edições:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
default_tools_approval_mode = "writes"   # leituras automáticas; gravações com aprovação
```

Na TUI, execute `/mcp` para confirmar a conexão. A extensão da IDE compartilha a mesma configuração. Consulte a [documentação MCP do Codex](https://developers.openai.com/codex/mcp) para ajustes de aprovação por ferramenta e listas de ferramentas permitidas ou bloqueadas.

### DeepSeek Harness (dsh)

O DeepSeek Harness conecta servidores MCP pela sua árvore de plugins. Adicione uma entrada `@deepseek-ai/dsh-mcp-client` por servidor ao patch do perfil ativo, em `$DSH_HOME/profiles/<profile>/cordis.patch.yml` (o padrão de `$DSH_HOME` é `~/.dsh`), ou ao `cordis.patch.yml` do diretório inicial:

```yaml
- id: dz6
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: dz6
    transport: stdio
    command: /path/to/dz6-mcp
    args: []
    toolCallTimeoutMs: 30000
```

Para aplicar uma configuração temporária sem editar o perfil:

```sh
dsh web --patch ./dz6.cordis.yml
```

As ferramentas chegam ao modelo como `mcp__dz6__open_file`, `mcp__dz6__read_bytes` e assim por diante. Reinicie o perfil após alterar o patch. Consulte o [README do pacote cliente MCP](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md) para conhecer `failOnStartupError`, `reconnect` e outros campos.

### OpenCode

Os servidores MCP ficam em `mcp.servers` no arquivo `opencode.jsonc`, globalmente em `~/.config/opencode/opencode.jsonc` ou na raiz do projeto. Use `disabled: true` para manter um servidor configurado sem conectá-lo; não existe um campo `enabled` nessa configuração:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "dz6": {
        "type": "local",
        "command": ["/path/to/dz6-mcp"]
      }
    }
  }
}
```

Ou use a CLI; acrescente `--global` para disponibilizá-lo em todos os projetos:

```sh
opencode mcp add dz6 -- /path/to/dz6-mcp
opencode mcp add --global dz6 -- /path/to/dz6-mcp
opencode mcp list
```

No Code Mode padrão, as ferramentas são agrupadas como `tools.dz6.<tool>(...)`. Defina `"codemode": false` no servidor para expô-las diretamente.

### Kilo Code

O Kilo lê configurações JSONC: `~/.config/kilo/kilo.jsonc` (global) e `kilo.jsonc` ou `.kilo/kilo.jsonc` (projeto, com precedência). Os servidores ficam na chave `mcp` do nível superior:

```jsonc
{
  "mcp": {
    "dz6": {
      "type": "local",
      "command": ["/path/to/dz6-mcp"],
      "enabled": true
    }
  }
}
```

Na extensão do VS Code, também é possível usar **Settings → MCP → Add Server**. A extensão antiga lê `mcp_settings.json` (global) e `.kilocode/mcp.json` (projeto), com a estrutura `mcpServers`:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": [],
      "disabled": false
    }
  }
}
```

### Pi

A CLI grava a configuração para você:

```sh
pi mcp add dz6 -- /path/to/dz6-mcp       # escopo de usuário (padrão)
pi mcp add -l dz6 -- /path/to/dz6-mcp    # escopo de projeto (projetos confiáveis)
pi mcp list
```

Ou edite `~/.pi/agent/mcp.json` (usuário) ou `.pi/mcp.json` (projeto), usando a mesma estrutura do Claude e do Cursor:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

Use `/mcp` na sessão para inspecionar as conexões e `/reload` após editar o arquivo. A configuração de projeto só é lida depois que o projeto é considerado confiável.

### Cursor / VS Code / clientes genéricos

Cursor, Windsurf, Cline e clientes semelhantes usam um objeto `mcpServers`:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": ["--readonly"]
    }
  }
}
```

O VS Code usa um objeto `servers` no nível superior de `.vscode/mcp.json`, ou a seção `mcp.servers` de `settings.json`:

```json
{
  "servers": {
    "dz6": {
      "type": "stdio",
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

### stdio direto

Qualquer cliente capaz de iniciar um processo e trocar mensagens JSON-RPC 2.0 delimitadas por quebras de linha pode usar o servidor. A sequência é `initialize` → `notifications/initialized` → `tools/list` / `tools/call`.

```python
#!/usr/bin/env python3
import json, subprocess

p = subprocess.Popen(
    ["/path/to/dz6-mcp", "--readonly"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
)

def call(msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())

call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "example", "version": "1"},
}})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
p.stdin.flush()

print(call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
    "name": "sections",
    "arguments": {"path": "/bin/true"},
}}))
```

O servidor responde com a versão do protocolo oferecida pelo cliente. As versões suportadas são `2024-11-05`, `2025-03-26` e `2025-06-18`.

## Conceitos fundamentais

### Sessões e abertura sob demanda

Cada conexão MCP possui um `ServerState` com um mapa de caminho canônico → `dz6::App`. A primeira ferramenta que referencia um caminho abre o arquivo. As chamadas seguintes reutilizam o mesmo documento, incluindo alterações pendentes, cursor e anotações. Use `open_file` para escolher explicitamente o modo somente leitura, `list_open_files` para consultar o cache e `close_file` para fechar um documento.

Vários arquivos podem permanecer abertos ao mesmo tempo. Não existe limite de arquivos por sessão.

### Modos de somente leitura

O modo somente leitura pode ser definido em dois lugares:

1. **No servidor**: `dz6-mcp --readonly` abre todos os arquivos sob demanda em modo somente leitura por padrão.
2. **Por arquivo**: `open_file` aceita `"readonly": true|false` e sobrescreve o padrão do servidor para aquele documento.

Se um documento já estiver aberto com outro modo solicitado, `open_file` o reabre, desde que não haja edições pendentes. O modo efetivo pode ser mais restritivo: se o processo não conseguir abrir o arquivo para gravação, por exemplo devido a permissões, o documento será somente leitura. `file_info` informa esse estado efetivo.

Documentos somente leitura rejeitam `write_bytes`, `fill`, `save` e `truncate`. `undo` é inofensivo, pois não há alterações de bytes pendentes. Anotações ainda podem ser preparadas em memória, mas só podem ser persistidas depois de reabrir o documento para gravação e salvá-lo. `dump` continua gravando no seu próprio `out_path`, e `log_level` / `logs_clear` continuam disponíveis.

### Bytes efetivos e alterações pendentes

As edições são mantidas no mapa `changed_bytes` do dz6, em memória. Elas ficam imediatamente visíveis para:

- `read_bytes`, `read_int`, `read_string`
- `search`, `search_all`
- `pattern_scan`
- `analyze`
- `dump`
- `read_at_address`

Somente `save` grava essas edições no disco. `undo` desfaz primeiro as alterações mais recentes. `truncate` é a exceção: modifica o arquivo imediatamente.

`strings` é a ferramenta de análise que percorre o mapeamento do arquivo no disco em vez de considerar as alterações pendentes.

As ferramentas estruturais (`headers`, `sections`, `symbols`, `address_translate`, `pe_info`, `elf_info`) analisam o arquivo como ele está no disco. Alterações de cabeçalhos ainda não salvas não aparecem nesses resultados.

### Anotações e arquivo auxiliar

Comentários, marcadores e blocos coloridos pertencem ao documento e são gravados em `<file>.dz6` (TOML) durante `save`, desde que o banco de dados do dz6 esteja habilitado, como ocorre por padrão. Fechar um documento sem salvar descarta as anotações não salvas. O formato é o mesmo da TUI, permitindo compartilhar anotações com sessões interativas do dz6.

### Convenções numéricas

- **Entradas**: offsets e comprimentos são números JSON decimais. Endereços em `address_translate` e `read_at_address` são strings e aceitam decimal ou hexadecimal com prefixo `0x` (`"0x401000"`). Dados hexadecimais aceitam espaços e os separadores `:`, `-`, `_`, com prefixo `0x` opcional.
- **Saídas**: offsets e endereços aparecem em campos decimais (`offset`, `start`, `end`) e strings hexadecimais (`offset_hex`, `start_hex`, `va`, `file_offset_hex`, …). Os dumps hexadecimais usam letras maiúsculas e espaços entre bytes.
- **Limitação de leitura**: `read_bytes`, `read_string`, `analyze` e `read_at_address` informam `truncated` ou o comprimento efetivo quando o intervalo solicitado ultrapassa o arquivo ou o limite interno.

### Resultados e erros

As ferramentas retornam objetos JSON. Resultados bem-sucedidos usam conteúdo estruturado MCP; o mesmo JSON também é disponibilizado como texto para clientes que não leem `structuredContent`. Erros definem `isError: true` e retornam um objeto estruturado:

```json
{ "error": "offset 0x100 is past end of file (0xff)" }
```

As mensagens de erro identificam o parâmetro inválido e o limite relevante para facilitar a correção. Os nomes de ferramentas, parâmetros, valores de protocolo e mensagens de erro permanecem em inglês nos exemplos desta documentação.

## Referência das ferramentas

São **39 ferramentas**, agrupadas abaixo. `RO` identifica ferramentas que anunciam `read_only_hint = true`; clientes podem usar essa indicação para aprovação automática. `truncate` também anuncia `destructive_hint = true`.

- **Arquivos (5)**: `open_file`, `close_file`, `list_open_files`, `file_info`, `goto`.
- **Leitura e análise (10)**: `read_bytes`, `read_int`, `read_string`, `headers`, `search`, `search_all`, `pattern_scan`, `strings`, `analyze`, `dump`.
- **Inspeção de binários (6)**: `sections`, `symbols`, `address_translate`, `read_at_address`, `pe_info`, `elf_info`.
- **Edição (5)**: `write_bytes`, `fill`, `undo`, `save`, `truncate`.
- **Anotações (9)**: `comment_set`, `comments_list`, `bookmark_add`, `bookmark_remove`, `bookmarks_list`, `bookmark_clear`, `block_add`, `blocks_list`, `block_clear`.
- **Diagnóstico (4)**: `server_info`, `log_level`, `logs_tail`, `logs_clear`.

### Arquivos

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `open_file` | ✓ | `path`, `readonly?` | `{opened, file}` com metadados. Reabre no modo solicitado quando ele difere do atual e não há edições pendentes. |
| `close_file` | – | `path`, `save?` | `{closed, path}`. `save=true` grava as edições pendentes antes de fechar; por padrão elas são descartadas. |
| `list_open_files` | ✓ | – | `{count, files[]}` com todos os documentos em cache. |
| `file_info` | ✓ | `path` | Tamanho, tipo detectado, modo somente leitura, indicador de alterações, alterações pendentes, cursor e contagens de anotações. |
| `goto` | ✓ | `path`, `offset` | Move o cursor e retorna `{offset, file_size}`. `offset` deve ser `< size`. |

As entradas de `file_info` / `list_open_files` contêm:

```json
{
  "path": "/abs/path",
  "size": 35664,
  "size_hex": "0x8b50",
  "type": "ELF",
  "readonly": false,
  "dirty": false,
  "pending_changes": 0,
  "offset": 0,
  "bookmarks": 0,
  "comments": 0,
  "blocks": 0
}
```

O cursor definido por `goto` é o ponto inicial padrão das chamadas de `search` para a frente.

### Leitura e análise

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `read_bytes` | ✓ | `path`, `offset`, `length?`, `format?`, `include_bytes?` | Representação hexadecimal e/ou ASCII com metadados do intervalo. |
| `read_int` | ✓ | `path`, `offset`, `size`, `signed?`, `endian?` | Valor decimal e bytes originais. |
| `read_string` | ✓ | `path`, `offset`, `encoding?`, `max_length?`, `stop_at_nul?` | Texto decodificado, comprimento em bytes e em caracteres. |
| `headers` | ✓ | `path` | Cabeçalhos PE ou ELF completos do analisador do dz6. |
| `search` | ✓ | Veja [Sintaxe de busca](#sintaxe-de-busca). | Primeiro offset encontrado ou `found: false`. |
| `search_all` | ✓ | Veja [Sintaxe de busca](#sintaxe-de-busca). | Até `max` offsets encontrados, em decimal e hexadecimal. |
| `pattern_scan` | ✓ | Veja [Varredura de padrões](#varredura-de-padrões). | Ocorrências de uma ou mais assinaturas nomeadas, com contexto. |
| `strings` | ✓ | `path`, `min_length?`, `max?`, `regex?`, `offset?`, `length?` | Sequências ASCII imprimíveis, com filtros opcionais por regex e intervalo. |
| `analyze` | ✓ | `path`, `offset?`, `length?` | Entropia de Shannon, proporção de bytes imprimíveis e quantidade de valores de byte distintos. |
| `dump` | – | `path`, `out_path`, `offset`, `length` | Grava o intervalo em `out_path`; retorna `{bytes_written}`. |

Detalhes e limites:

- **`read_bytes`**: `length` tem padrão 256 e limite de 1 MiB. `format` aceita `both` (padrão), `hex` ou `ascii`. `include_bytes=true` acrescenta um array JSON de valores de bytes. A leitura termina no fim do arquivo; `truncated` indica que havia menos bytes disponíveis do que o solicitado. Um offset além do fim do arquivo gera erro. Considera as edições pendentes.
- **`read_int`**: `size` deve ser `1`, `2`, `4` ou `8`. `endian` aceita `little`/`le` (padrão) ou `big`/`be`. `signed` tem padrão false. Retorna erro se o inteiro ultrapassar o fim do arquivo. Considera as edições pendentes.
- **`read_string`**: `encoding` aceita `utf8` (padrão), `latin1`, `utf16le` ou `utf16be`. `max_length` tem padrão 256 e limite de 1 MiB. `stop_at_nul` tem padrão true. Sequências inválidas são substituídas, não rejeitadas.
- **`headers`**: retorna a estrutura de cabeçalhos do dz6. Para PE: `dos_header`, `coff_header`, `optional_header` (incluindo diretórios de dados), `sections`, `imports` e `exports`. Para ELF: `class`, `endianness`, `header`, `program_headers`, `sections`, `symbols`, `dynamic_symbols` e `relocations`. Para outros formatos: `{format, parsed: false, message}`, permitindo examinar arquivos desconhecidos sem gerar erro de formato.
- **`strings`**: percorre sequências ASCII imprimíveis (`is_ascii_graphic()` ou espaço) com comprimento mínimo padrão de 4. `regex` **não diferencia maiúsculas de minúsculas**. `max` tem padrão 3000. `offset`/`length` filtram pelo offset inicial da string. Lê o mapeamento no disco, sem as edições pendentes.
- **`analyze`**: calcula a entropia de Shannon em bits por byte (0–8). `printable_ratio` é a proporção de bytes imprimíveis (0–1). `unique_bytes` é a quantidade de valores de byte distintos (0–256). Por padrão analisa o restante do arquivo, com limite de 64 MiB. Considera as edições pendentes.
- **`dump`**: grava o intervalo efetivo, incluindo edições pendentes, em `out_path`. `length` deve ser maior que zero. O destino é criado ou sobrescrito com `std::fs::write`; os diretórios pais não são criados.

Exemplo de leitura e decodificação de um inteiro:

```json
{ "path": "/tmp/sample.bin", "offset": 0, "size": 2, "endian": "little" }
```

```json
{
  "path": "/tmp/sample.bin",
  "offset": 0,
  "size": 2,
  "signed": false,
  "endian": "little",
  "decimal": "23117",
  "raw_hex": "4D 5A"
}
```

### Inspeção de binários

Essas ferramentas analisam o executável com goblin. Retornam erro para arquivos que não sejam PE nem ELF. Use `headers` caso prefira um resultado com `parsed: false`.

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `sections` | ✓ | `path` | Seções PE/ELF e cabeçalhos de programa ELF com endereços, offsets, flags, entropia e segmento associado. |
| `symbols` | ✓ | `path`, `name_regex?`, `kind?`, `dynamic_only?`, `global_only?`, `max?` | `.symtab`/`.dynsym` de ELF ou exportações/importações de PE. |
| `address_translate` | ✓ | `path`, `address?` **ou** `offset?`, `kind?` | Endereço ↔ offset de arquivo, além de RVA, seção e segmento. |
| `read_at_address` | ✓ | `path`, `address`, `kind?`, `length?`, `format?`, `include_bytes?` | Bytes em um VA/RVA, considerando edições pendentes. |
| `pe_info` | ✓ | `path` | Diretórios e metadados PE: PDB, TLS, certificados, recursos, CLR, cabeçalho Rich, overlay etc. |
| `elf_info` | ✓ | `path` | Interpretador ELF, tags dinâmicas, NEEDED/SONAME/RPATH/RUNPATH, notas e segmentos. |

#### `sections`

Para PE, cada seção informa:

```json
{
  "name": ".text",
  "virtual_address": "0x1000",
  "virtual_size": "0x7fa10",
  "va_start": "0x140001000",
  "va_end": "0x140080a10",
  "file_offset": "0x400",
  "file_size": "0x7fc00",
  "entropy": 6.21,
  "characteristics": "0x60000020",
  "flags": {
    "readable": true, "writable": false, "executable": true,
    "code": true, "initialized_data": false, "uninitialized_data": false
  }
}
```

Para ELF, cada seção acrescenta `type`, `type_name`, `alloc`, `writable`, `executable`, `addr`, `offset`, `size`, `addralign`, `entsize` e o índice do `segment` associado. A resposta também inclui `segments[]` com `type_name` (`LOAD`, `DYNAMIC`, `INTERP`, `NOTE`, …), flags decodificadas `readable` / `writable` / `executable`, `offset`, `vaddr`, `paddr`, `filesz`, `memsz` e `align`. A entropia é calculada sobre os bytes brutos da seção.

#### `symbols`

Parâmetros comuns:

- `name_regex`: expressão regular Rust aplicada ao nome do símbolo.
- `kind`: `all` (padrão), `function`, `object`, `import`, `export`. Aliases: `func`, `data`, `undefined`, `defined`.
- `dynamic_only`: em ELF, força o uso de `.dynsym` mesmo quando `.symtab` existe.
- `global_only`: em ELF, exclui símbolos locais.
- `max`: padrão 1000, limitado a 10000. `truncated` indica se havia mais resultados.

Em ELF, `.symtab` é usada quando existe, a menos que `dynamic_only` esteja definido; normalmente ela também contém as entradas de `.dynsym`. Caso contrário, usa-se `.dynsym`. As entradas incluem `name`, `source` (`symtab`/`dynsym`), `kind` (`import`/`export`/`local`), `value`, `size`, `type` (`FUNC`, `OBJECT`, …), `bind` (`LOCAL`, `GLOBAL`, `WEAK`, …), `visibility`, `shndx`, `section` e `file_offset` quando o endereço corresponde a um intervalo do arquivo.

Em PE, apenas `all`, `import` e `export` são aplicáveis. Solicitar `function` ou `object` retorna um erro explicativo. Importações incluem `dll`, `ordinal`, `rva` e `file_offset`; exportações incluem `rva`, `va`, `file_offset` e `size`.

#### `address_translate`

Forneça exatamente um destes parâmetros: `address` (string decimal ou hexadecimal com `0x`) ou `offset` (número):

```json
{ "path": "/tmp/sample.exe", "address": "0x140001000" }
```

```json
{
  "format": "PE",
  "input": { "kind": "va", "value": "0x140001000" },
  "mapped": true,
  "file_offset": 1024,
  "file_offset_hex": "0x400",
  "va": "0x140001000",
  "rva": "0x1000",
  "section": ".text",
  "segment": null
}
```

- PE: `kind` aceita `va` (padrão) ou `rva`. O RVA é resolvido pela tabela de seções, ou diretamente na região de cabeçalhos.
- ELF: `kind` deve ser `va`; entradas RVA são rejeitadas. O mapeamento usa segmentos `PT_LOAD` com `p_filesz`, recorrendo a seções com endereço em layouts incomuns sem cabeçalhos de programa.
- Entradas sem mapeamento retornam erro, em vez de um resultado enganoso com `mapped: false`.

#### `read_at_address`

Combina `address_translate` com `read_bytes`. Exemplo com um endereço virtual PE:

```json
{ "path": "/tmp/sample.exe", "address": "0x140001000", "kind": "va", "length": 32 }
```

`length` tem padrão 256 e limite de 1 MiB. `format` aceita `both` (padrão), `hex` ou `ascii`. A resposta inclui os campos da conversão, além de `hex`, `ascii`, `length`, `requested_length` e `truncated`. A leitura usa os bytes efetivos, tornando as alterações visíveis antes do salvamento.

#### `pe_info`

Retorna os metadados exclusivos de PE em um objeto:

| Campo | Conteúdo |
| --- | --- |
| `is_64`, `is_dll`, `machine`, `machine_id` | Arquitetura e tipo da imagem. |
| `image_base`, `entry_point_rva`, `entry_point_va` | Endereços de carregamento. |
| `checksum`, `size_of_image`, `subsystem`, `dll_characteristics` | Valores do cabeçalho opcional. |
| `data_directories[]` | `index`, `name` (export, import, resource, exception, certificate, base_relocation, debug, architecture, global_ptr, tls, load_config, bound_import, iat, delay_import, clr_runtime), `virtual_address`, `va`, `size`. |
| `debug` | CodeView PDB70/PDB20 (`format`, `guid` ou `signature`, `age`, `path`) e booleanos `vcfeature`, `extended_dll_characteristics`, `reproducible_build`, `pogo`. |
| `tls` | Intervalo de dados brutos, endereço do índice, endereço dos callbacks, callbacks (`va[]`), slot, tamanho de preenchimento com zeros e características. |
| `exceptions` | `{function_count}` do diretório de exceções (`.pdata`). |
| `relocations` | `{block_count}` do diretório de realocações de base. |
| `load_config` | Tamanho, cookie de segurança, tabela/contagem de manipuladores SE, flags de proteção, contagem de funções CF e ponteiro de verificação CF. |
| `certificates[]` | `length`, `revision`, `type` e `bytes` de cada entrada Authenticode. |
| `resources` | Contagens de entradas por nome/ID e indicação de informações de versão e manifesto. |
| `clr` | Versão do runtime .NET, flags, RVA/tamanho dos metadados, token/RVA do ponto de entrada e tamanho da assinatura de nome forte. |
| `rich_header` | `key` decodificada e `entries[]` (`product_id`, `build`, `count`). |
| `overlay` | `offset`, `size` e `entropy` quando há dados após a última seção. |

A ferramenta informa a **presença** desses elementos, sem atestar sua confiabilidade: certificados não são validados e o cabeçalho Rich é apenas decodificado.

#### `elf_info`

Retorna os metadados exclusivos de ELF:

| Campo | Conteúdo |
| --- | --- |
| `class`, `endianness`, `object_type`, `machine`, `machine_id` | Identificação ELF (`ELF32`/`ELF64`, `REL`/`EXEC`/`DYN`/`CORE`). |
| `entry_point`, `interpreter` | Endereço de entrada e caminho `PT_INTERP`. |
| `soname`, `needed`, `rpath`, `runpath` | Metadados de vinculação dinâmica, também presentes em `dynamic`. |
| `notes[]` | `name`, `type`, `type_name`, `description_hex`, `description_ascii`; inclui o build-id GNU e a tag ABI quando presentes. |
| `dynamic` | `flags`, `flags_1`, `init`, `fini`, `init_array`, `fini_array`, `rela`, `rel`, `pltgot`, `textrel`, contagens de definições/requisitos de versão e até 256 entradas brutas `{tag, value}`. `entries_truncated` indica quando esse limite foi atingido. |
| `segments[]` | Cabeçalhos de programa com tipo e flags R/W/X decodificados. |

### Edição

As edições permanecem em memória e ficam imediatamente visíveis às ferramentas que leem os bytes efetivos. Somente `save` as grava no disco. `truncate` é imediato.

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `write_bytes` | – | `path`, `offset`, `data` | `{bytes_written, pending_changes, saved: false}`. |
| `fill` | – | `path`, `offset`, `length`, `value?` ou `kind?` | Comprimento preenchido, valor do byte e alterações pendentes. |
| `undo` | – | `path`, `steps?` | Quantidade de edições desfeitas e alterações ainda pendentes. |
| `save` | – | `path` | `{bytes_written, database_saved, pending_changes, file_size}`. |
| `truncate` | – (destrutiva) | `path`, `offset`, `mode` | Novo tamanho. Imediato e irreversível. |

- **`write_bytes`**: `data` é hexadecimal; espaços e os separadores `:`, `-`, `_` são ignorados, e o prefixo `0x` é opcional. Uma alteração pode atravessar limites de seções, mas não o fim do arquivo.
- **`fill`**: `kind` aceita `zero` (0x00) ou `nop` (0x90). Se `kind` e `value` estiverem presentes, `kind` tem prioridade. `length` deve ser maior que zero.
- **`undo`**: desfaz primeiro as edições pendentes mais recentes. Não desfaz `truncate`, que já modificou o arquivo.
- **`save`**: aplica as edições ao arquivo e depois grava o auxiliar `.dz6`. Retorna a quantidade de posições de bytes gravadas e indica se o banco de dados foi salvo. Não cria backup.
- **`truncate`**: `mode: "after"` mantém os bytes até `offset`, inclusive; `mode: "before"` remove tudo antes de `offset` e desloca o restante para a posição 0. Exige permissão de gravação e **nenhuma edição pendente**. É irreversível.

Fluxo típico de alteração:

```text
write_bytes {"path": "/tmp/app.exe", "offset": 4096, "data": "90 90 90"}
read_bytes  {"path": "/tmp/app.exe", "offset": 4096, "length": 8}
undo        {"path": "/tmp/app.exe"}
# ou, quando a alteração estiver correta:
save        {"path": "/tmp/app.exe"}
```

### Anotações

São persistidas em `<file>.dz6` durante `save`, desde que o banco de dados do dz6 esteja habilitado, como ocorre por padrão. O arquivo auxiliar é compartilhado com a TUI.

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `comment_set` | – | `path`, `offset`, `comment` | Define/substitui um comentário; uma string vazia o remove. |
| `comments_list` | ✓ | `path` | Comentários ordenados por offset, em decimal e hexadecimal. |
| `bookmark_add` | – | `path`, `offset` | Adiciona um marcador (máximo 8); duplicatas retornam `already_bookmarked`. |
| `bookmark_remove` | – | `path`, `offset?` | Remove um marcador ou o mais recente quando `offset` é omitido. |
| `bookmarks_list` | ✓ | `path` | Todos os marcadores, em decimal e hexadecimal. |
| `bookmark_clear` | – | `path` | Remove todos os marcadores. |
| `block_add` | – | `path`, `start`, `end`, `bg_color?`, `fg_color?` | Marca um intervalo inclusivo de bytes. |
| `blocks_list` | ✓ | `path` | Todos os blocos coloridos com cores `0x00RRGGBB`. |
| `block_clear` | – | `path` | Remove todos os blocos coloridos. |

- Os offsets de comentários e marcadores devem ser `< size`; os intervalos de blocos são validados.
- O limite de marcadores é 8, como no dz6.
- As cores usam `0x00RRGGBB`. Quando omitidas, o dz6 escolhe cores aleatórias.
- `start` e `end` são inclusivos.
- Anotações pertencem ao estado do documento e só são persistidas após `save`.

### Diagnóstico

O cliente MCP recebe o protocolo por stdout; estas ferramentas permitem consultar o estado e os logs do próprio servidor.

| Ferramenta | RO | Parâmetros | Retorno |
| --- | --- | --- | --- |
| `server_info` | ✓ | – | Nome, versão, PID, tempo de execução, transporte, modo somente leitura padrão, nível/arquivo de log, linhas de log em memória, arquivos abertos e quantidade de ferramentas. |
| `log_level` | – | `level?` | Filtro atual quando omitido; caso contrário, define o filtro e informa `changed: true`. |
| `logs_tail` | ✓ | `limit?` | Até `limit` linhas recentes (padrão 100) do buffer circular de 2000 linhas, com as mais recentes por último. |
| `logs_clear` | – | – | Esvazia o buffer circular e retorna quantas linhas foram removidas. |

`log_level` aceita `trace`, `debug`, `info`, `warn`, `error`, `off` ou uma lista de diretivas EnvFilter, como `dz6_mcp=debug,rmcp=info`. Valores simples inválidos são rejeitados; listas de diretivas são validadas por `EnvFilter`.

Para depurar: chame `log_level` com `{"level": "debug"}`, reproduza o problema e depois chame `logs_tail` com `{"limit": 50}`.

## Sintaxe de busca

`search` e `search_all` compartilham os parâmetros abaixo:

| Parâmetro | Padrão | Significado |
| --- | --- | --- |
| `needle` | – | Texto ou padrão hexadecimal. Não pode ser vazio. |
| `mode` | `text` | `text` ou `hex`. |
| `direction` | `forward` | `forward` ou `backward`. |
| `offset` | `search`: cursor (para a frente) / EOF (para trás); `search_all`: `0` / EOF | Offset inicial. Em buscas para trás, é um **limite superior inclusivo**. |
| `next` | `false` | Apenas `search`: ignora a posição atual e retorna a ocorrência seguinte/anterior. |
| `ignore_case` | `false` | Ignora diferenças entre maiúsculas e minúsculas ASCII, somente em texto. |
| `smart_case` | `false` | Desabilita `ignore_case` quando o padrão contém letra maiúscula. |
| `wrapscan` | `false` | Continua a busca ao atingir o fim/início do arquivo, apenas em `search`. |
| `max` | `100` | Apenas `search_all`; limitado a 10000. |

O modo hexadecimal usa a sintaxe do dz6:

| Padrão | Correspondência |
| --- | --- |
| `4D5A` | Bytes literais `4D 5A`. |
| `4D5A????0000` | `4D 5A`, quaisquer dois bytes, `00 00`. |
| `4D5A[00-ff]0000` | `4D 5A`, um byte em `00..=ff`, `00 00`. |
| `[41-5a]` | Um byte entre `41` e `5a`, inclusive. |

Os dígitos hexadecimais devem formar bytes completos e estar em quantidade par. Para correspondências no nível de nibble, use `pattern_scan`.

Semântica:

- As buscas usam os **bytes efetivos**, incluindo as edições pendentes.
- Resultados para a frente são crescentes; para trás, decrescentes. Todos os offsets são absolutos.
- A busca para trás inclui o offset de limite, diferentemente da TUI do dz6, que pode deixar de considerar o último byte.
- Padrões hexadecimais com curingas são compilados em uma regex de bytes e retornam ocorrências sem sobreposição. Hexadecimal literal e texto podem retornar ocorrências sobrepostas.
- `search_all` define `truncated: true` quando para ao atingir `max`.
- `search` retorna `{found, offset, offset_hex, start_offset, …}`. Não encontrar uma ocorrência não é um erro.

Exemplo:

```json
{
  "path": "/tmp/sample.exe",
  "needle": "4D5A????0000",
  "mode": "hex",
  "direction": "forward",
  "offset": 0
}
```

## Varredura de padrões

`pattern_scan` complementa `search` com foco em assinaturas. Retorna as ocorrências de um ou mais padrões, permite nomeá-los e oferece uma sintaxe mais ampla.

```json
{
  "path": "/tmp/sample.bin",
  "patterns": [
    { "name": "elf", "pattern": "7F454C46" },
    { "name": "call-rel32", "pattern": "E8????????" },
    { "name": "pe-exports", "pattern": "50450000{0-8}64" }
  ],
  "offset": 0,
  "length": 65536,
  "max": 200,
  "context": 8
}
```

Parâmetros:

| Parâmetro | Padrão | Significado |
| --- | --- | --- |
| `path` | – | Arquivo a examinar. |
| `pattern` | – | Forma abreviada para um padrão sem nome. Ignorado quando `patterns` está presente. |
| `patterns` | – | Array de `{name?, pattern, mode?, ignore_case?}`. É necessário fornecer pelo menos uma fonte de padrões. |
| `mode` | `hex` | Modo padrão para padrões sem modo próprio: `hex` ou `text`. |
| `offset` | `0` | Primeiro byte da janela de varredura. |
| `length` | Restante do arquivo | Tamanho da janela de varredura. |
| `max` | `100` | Máximo total de ocorrências, limitado a 10000. |
| `context` | `0` | Bytes antes/depois de cada ocorrência, limitado a 64. |
| `first_only` | `false` | Retorna somente a ocorrência mais próxima do início. |
| `include_bytes` | `true` | Inclui os bytes encontrados em hexadecimal. |

Sintaxe hexadecimal, que amplia a sintaxe do dz6:

| Sintaxe | Significado | Exemplo |
| --- | --- | --- |
| `4865` / `48 65` | Bytes literais; espaços são ignorados. | `4D5A` |
| `??` | Um byte qualquer. | `4D5A??0000` |
| `A?` | Nibble superior fixo (`0xA0..=0xAF`). | `4?5A` |
| `?A` | Nibble inferior fixo (`0x0A, 0x1A, …, 0xFA`). | `?A` |
| `[00-ff]`, `[41]` | Intervalo inclusivo de bytes ou um byte específico. | `[41-5A]` |
| `{n}`, `{n-m}` | Exatamente `n` ou de `n` a `m` bytes arbitrários. | `AA{2-4}BB` |
| `(AA\|BB 43)` | Alternativas de sequências de bytes. | `(E8\|E9)????????` |
| `VALUE:MASK` | Correspondência com máscara sobre todo o padrão. | `4D5A0000:FFFF0000` |

Padrões com máscara usam o teste de bits `(b & mask[i]) == (value[i] & mask[i])`, em que `b` é o byte da posição `i`. Portanto, `4D5A0000:FFFF0000` exige `4D 5A` e ignora os dois bytes seguintes. `05:0F` corresponde a qualquer byte cujo nibble inferior seja `5`.

Semântica e limites:

- Padrões literais de hexadecimal e texto usam `memchr` e retornam ocorrências **sobrepostas**: buscar `AA` em `AA AA AA` retorna offsets 0, 1 e 2.
- Padrões com construções avançadas são compilados em regex de bytes e retornam ocorrências **sem sobreposição**.
- Intervalos de bytes arbitrários são limitados a 65536 bytes.
- Construções avançadas são aplicadas à janela de varredura; uma ocorrência não pode ultrapassar seus limites.
- `first_only` retorna a ocorrência mais próxima do início entre todos os padrões.
- Resultados são ordenados por offset e depois pela ordem dos padrões. Incluem `pattern`, `name`, `mode`, `offset`, `offset_hex`, `length` e, opcionalmente, `bytes`, `context_offset`, `context_before`, `context_after`.
- A resposta inclui a lista de padrões compilados, `count` e `truncated`.
- A varredura usa bytes efetivos, incluindo edições pendentes.
- Padrões inválidos retornam erro com a identificação do padrão e do problema.

Trecho de uma resposta de exemplo:

```json
{
  "count": 1,
  "truncated": false,
  "matches": [
    {
      "pattern": "7F454C46",
      "name": "elf",
      "mode": "hex",
      "offset": 0,
      "offset_hex": "0x0",
      "length": 4,
      "bytes": "7F 45 4C 46",
      "context_offset": 0,
      "context_before": "",
      "context_after": "02 01 01 00 00 00 00 00"
    }
  ]
}
```

## Referência PE/ELF

### Qual ferramenta devo usar?

| Pergunta | Ferramenta |
| --- | --- |
| Este arquivo é PE/ELF? O que diz o cabeçalho? | `headers` |
| Onde ficam as seções/segmentos? Quais são executáveis ou apresentam indícios de empacotamento? | `sections` |
| Quais funções, importações e exportações existem? | `symbols` |
| Qual offset de arquivo corresponde a este endereço? | `address_translate` |
| Quais bytes estão neste endereço? | `read_at_address` |
| Quais PDBs, callbacks TLS, certificados, recursos ou dados de overlay existem neste PE? | `pe_info` |
| Quais bibliotecas, RPATH, build-id ou tags dinâmicas existem neste ELF? | `elf_info` |

### Regras de conversão de endereços

**PE**

```text
VA  = image_base + RVA
RVA = VA - image_base

região de cabeçalhos: RVA < SizeOfHeaders       → offset = RVA
região de seção:      RVA em [VA, VA + span)    → offset = PointerToRawData + (RVA - VA)
                      span = max(VirtualSize, SizeOfRawData)
                      o resultado deve ficar dentro de SizeOfRawData
```

A conversão inversa mapeia diretamente offsets de cabeçalhos e, para as demais regiões, usa `PointerToRawData..PointerToRawData + SizeOfRawData`. Entradas inferiores a `image_base` são rejeitadas em consultas VA. Use `kind: "rva"` quando seu desassemblador apresentar RVAs.

**ELF**

```text
VA → offset: primeiro PT_LOAD em que p_vaddr <= va < p_vaddr + p_filesz
             offset = p_offset + (va - p_vaddr)
             alternativa: seção em que sh_addr <= va < sh_addr + sh_size

offset → VA: primeiro PT_LOAD em que p_offset <= off < p_offset + p_filesz
             va = p_vaddr + (off - p_offset)
             alternativa: seção em que sh_offset <= off < sh_offset + sh_size
```

Usa-se `p_filesz`, e não `p_memsz`, para offsets de arquivo porque `.bss` não possui bytes correspondentes no arquivo. A associação de seções a segmentos usa `p_memsz`, mantendo `.bss` atribuída ao segmento correto.

### Cobertura e limitações

- **Formatos**: PE (PE32/PE32+) e ELF (ELF32/ELF64, little endian ou big endian). O dz6 detecta Mach-O, mas estas ferramentas não o analisam; `headers` retorna `parsed: false`.
- **Sem desassemblagem, referências cruzadas ou descompilação.** O dz6-mcp é um editor e analisador de bytes. Use um desassemblador ou um provedor REA para essas tarefas.
- **Símbolos PE**: `symbols` expõe exportações/importações, não a tabela de símbolos COFF.
- **Recursos PE**: contagens resumidas e indicação de versão/manifesto, sem percorrer toda a árvore de recursos.
- **Certificados**: apenas presença e metadados. PKCS#7/Authenticode não é validado.
- **Símbolos ELF**: preferência por `.symtab` quando presente; caso contrário, `.dynsym`. Nomes de versões de símbolos não são resolvidos; `elf_info` informa contagens de definições/requisitos de versão.
- **Notas ELF**: leitura primeiro dos segmentos de notas e depois das seções de notas.
- **Tags dinâmicas ELF**: apresentadas como pares brutos `{tag, value}`, limitados aos primeiros 256.
- **Ferramentas estruturais leem o mapeamento no disco**; alterações pendentes em cabeçalhos só aparecem após `save` ou reabertura.
- **Arquivos malformados ou empacotados**: goblin pode rejeitar arquivos que a TUI do dz6 ainda exibe como bytes brutos. Nesses casos, use `read_bytes`, `search` e `pattern_scan`, que não exigem um cabeçalho válido.

## Fluxos de trabalho

### Triagem de um arquivo desconhecido

```text
file_info    {"path": "/tmp/sample.bin"}
analyze      {"path": "/tmp/sample.bin"}
strings      {"path": "/tmp/sample.bin", "min_length": 6, "max": 200}
pattern_scan {"path": "/tmp/sample.bin", "patterns": [
               {"name": "mz",  "pattern": "4D5A"},
               {"name": "elf", "pattern": "7F454C46"},
               {"name": "zip", "pattern": "504B0304"},
               {"name": "png", "pattern": "89504E470D0A1A0A"}
             ]}
read_bytes   {"path": "/tmp/sample.bin", "offset": 0, "length": 128}
```

Entropia alta e poucas strings sugerem compressão ou criptografia. Se o contêiner for PE, consulte também as informações de seções e overlay em `sections` / `pe_info`.

### Triagem de PE

```text
open_file          {"path": "/tmp/sample.exe"}
file_info          {"path": "/tmp/sample.exe"}
headers            {"path": "/tmp/sample.exe"}
sections           {"path": "/tmp/sample.exe"}
pe_info            {"path": "/tmp/sample.exe"}
symbols            {"path": "/tmp/sample.exe", "kind": "import", "name_regex": "^Win"}
address_translate  {"path": "/tmp/sample.exe", "address": "0x140001000"}
read_at_address    {"path": "/tmp/sample.exe", "address": "0x140001000", "length": 64}
```

Consulte `debug.pdb.path` para caminhos de compilação, `tls.callbacks` para callbacks TLS, `certificates` para dados de assinatura, `resources.manifest` para informações de UAC e `overlay` para dados anexados ao arquivo. A entropia de `sections` ajuda a identificar seções empacotadas ou criptografadas.

### Triagem de ELF

```text
elf_info           {"path": "/bin/ls"}
sections           {"path": "/bin/ls"}
symbols            {"path": "/bin/ls", "kind": "function", "name_regex": "main|init"}
address_translate  {"path": "/bin/ls", "address": "0x2000"}
read_at_address    {"path": "/bin/ls", "address": "0x2000", "length": 32}
```

`elf_info` fornece o interpretador, as bibliotecas NEEDED, RPATH/RUNPATH e build-id, útil para localizar símbolos de depuração correspondentes. `symbols` com `dynamic_only` reflete os símbolos visíveis ao vinculador dinâmico. Os endereços destes exemplos são ilustrativos; obtenha os valores reais em `headers` / `sections` ou no desassemblador.

### Varredura de assinaturas

Encontre chamadas e saltos indiretos e instruções `call rel32`, com contexto:

```json
{
  "path": "/tmp/sample.exe",
  "patterns": [
    { "name": "call-rel32", "pattern": "E8????????" },
    { "name": "jmp-rel32", "pattern": "E9????????" },
    { "name": "indirect", "pattern": "(FF15|FF25)" },
    { "name": "int3-pad", "pattern": "CC{4-16}" }
  ],
  "max": 500,
  "context": 16
}
```

Encontre um valor com máscara, como a assinatura PE `MZ`, ignorando os dois bytes seguintes:

```json
{ "path": "/tmp/sample.bin", "pattern": "4D5A0000:FFFF0000", "max": 50 }
```

A forma `VALUE:MASK` não usa um token de curinga: cada bit zero da máscara ignora o bit correspondente. Assim, `4D5A0000:FFFF0000` corresponde a `4D 5A` seguido de quaisquer dois bytes.

### Alterar e verificar

```text
write_bytes {"path": "/tmp/sample.exe", "offset": 4096, "data": "90 90 90"}
read_bytes  {"path": "/tmp/sample.exe", "offset": 4096, "length": 16}
save        {"path": "/tmp/sample.exe"}
```

`read_bytes` vê a alteração em memória imediatamente. Se estiver incorreta, chame `undo` antes de `save`. `save` também grava o arquivo auxiliar `<file>.dz6`.

Para preencher com instruções NOP:

```text
fill {"path": "/tmp/sample.exe", "offset": 4096, "length": 12, "kind": "nop"}
```

### Engenharia reversa sem Ghidra com REA

`dz6-mcp` e [REA](https://github.com/mentebinaria/rea) são complementares:

- **REA** fornece a camada de análise: Rizin, GNU objdump, GDB e Frida (`execute_rizin_command`, `inspect_with_objdump`, depuradores), além de provedores opcionais para descompilação.
- **dz6-mcp** fornece os dados exatos no nível de bytes: conteúdo, padrões, estruturas PE/ELF, conversão VA↔offset e preparação/salvamento de alterações.

Exemplo de fluxo sem Ghidra:

```text
REA:  execute_rizin_command {"path": "/tmp/sample", "command": "aaa;afl"}          # funções
REA:  execute_rizin_command {"path": "/tmp/sample", "command": "aaa;pdf @ sym.main"} # desassemblagem
dz6:  address_translate  {"path": "/tmp/sample", "address": "0x401234"}
dz6:  read_at_address    {"path": "/tmp/sample", "address": "0x401234", "length": 64}
dz6:  pattern_scan       {"path": "/tmp/sample", "pattern": "E8????????", "max": 100}
dz6:  write_bytes        {"path": "/tmp/sample", "offset": 4660, "data": "90 90"}
dz6:  save               {"path": "/tmp/sample"}
REA:  inspect_with_objdump {"path": "/tmp/sample", "operation": "file_headers"}
```

REA registra `artifact_sha256_after` e `artifact_changed`; repetir uma inspeção REA após `save` confirma a alteração no disco. `execute_rizin_command` inicia um processo novo por chamada, por isso precisa de comandos encadeados (`aaa;afl`, `aaa;pdf @ sym.main`, `axt @ 0x...`). Sem um provedor de análise profunda, use Rizin/objdump/GDB do REA para inspeção e desassemblagem e dz6-mcp para bytes exatos, estruturas e alterações.

### Anotar durante o trabalho

```text
comment_set  {"path": "/tmp/sample.exe", "offset": 4096, "comment": "entry thunk"}
bookmark_add {"path": "/tmp/sample.exe", "offset": 4096}
block_add    {"path": "/tmp/sample.exe", "start": 4096, "end": 4127, "bg_color": 3368601}
comments_list {"path": "/tmp/sample.exe"}
save         {"path": "/tmp/sample.exe"}
```

### Sessões por script

Qualquer cliente JSON-RPC pode controlar o servidor. Mantenha um processo por sessão para preservar o cache de documentos, as alterações pendentes e as anotações. Use `close_file` para reiniciar o estado de um documento e `--readonly` para abrir entradas não confiáveis por padrão em modo somente leitura.

## Arquitetura

| Caminho | Responsabilidade |
| --- | --- |
| `src/main.rs` | Interpretação da CLI, inicialização dos logs e transporte stdio. |
| `src/server.rs` | `Dz6Server`, composição dos roteadores, logs de chamadas e instruções MCP. |
| `src/state.rs` | `ServerState` e `Document`: caminhos canônicos, abertura sob demanda, modo somente leitura e fechamento. |
| `src/ops.rs` | Operações sem TUI: leituras, intervalos efetivos, busca, edição, salvamento, truncamento, serialização de cabeçalhos e strings. |
| `src/pattern.rs` | Mecanismo de assinaturas: tradução e varredura de padrões hexadecimais. |
| `src/binary.rs` | Estruturas PE/ELF detalhadas, símbolos, conversão de endereços e metadados PE/ELF. |
| `src/tools/*.rs` | Interface MCP, com um roteador por grupo. |
| `src/logging.rs` | Assinante de tracing, `EnvFilter` recarregável, gravação simultânea em destinos de log e buffer circular de 2000 linhas. |

Fluxo de dados de uma leitura: JSON-RPC → `rmcp` → método da ferramenta → `ServerState::open_doc` → `ops` / `binary` → JSON.

## Solução de problemas

As mensagens de erro do servidor permanecem em inglês.

| Sintoma | Causa provável | Solução |
| --- | --- | --- |
| “server not connected” / nenhuma ferramenta | `command` aponta para um diretório, ou o executável foi movido/recompilado em outro local. | Use o caminho absoluto do executável (`…/target/release/dz6-mcp`). Verifique com `codex mcp get dz6`, `claude mcp get dz6` ou o painel MCP do cliente. |
| Novas ferramentas não aparecem após atualizar | O cliente manteve o resultado antigo de `tools/list` em cache. | Reconecte ou reinicie a sessão. `server_info` deve informar `tools: 39`. |
| O servidor encerra imediatamente | Opção de CLI inválida, `--log-file` sem permissão de gravação ou incompatibilidade da biblioteca dz6. | Execute o binário com `-v` e consulte stderr. |
| Não há logs por chamada | O nível padrão é `warn`. | Inicie com `-v` ou chame `log_level {"level": "info"}`. |
| `save` falha por falta de permissão | Arquivo aberto em modo somente leitura ou sem permissão de gravação para o processo. | Reabra com `open_file {"path": ..., "readonly": false}` e verifique as permissões. |
| “file is open with pending changes; save or discard them before changing its read-only mode” | `open_file` tentou mudar o modo de um documento com alterações pendentes. | Use `save`, desfaça todas as edições com `undo` ou use `close_file` antes. |
| “unsaved changes exist; save or undo them before truncating” | `truncate` rejeita arquivos com edições pendentes. | Execute `save` ou `undo` antes. |
| “offset … is past end of file” | Offset incompatível com o tamanho do arquivo. | Consulte `file_info` e mantenha `offset`/`length` dentro de `size`. |
| “RVA is only meaningful for PE files” | `kind: "rva"` usado em ELF. | Omita `kind`; ELF usa endereços VA. |
| “symbol kind … is not available for PE files” | `kind: "function"`/`"object"` usado em PE. | Use `all`, `import` ou `export`. |
| `sections`/`pe_info`/`elf_info` rejeita um arquivo | Não é PE/ELF válido, está malformado ou empacotado. | Verifique com `headers` e depois use `read_bytes`/`search`/`pattern_scan`. |
| Respostas muito grandes ou timeout do cliente | `max`/`length`/`strings` sem restrição adequada. | Use `max`, `context`, `offset`/`length` e aumente o timeout de ferramentas do cliente. |
| JSON-RPC corrompido ou falhas | Algum código escreveu em stdout. | Evite `print!`/`println!` nos caminhos do servidor e da biblioteca; logs devem ir para stderr. |
| `strings` não encontra uma edição pendente | `strings` percorre o mmap, sem aplicar as edições em memória. | Execute `save` antes ou use `search`/`read_bytes`/`pattern_scan`. |
| Alterações de cabeçalho PE não aparecem em `sections` | Ferramentas estruturais analisam o mapeamento no disco. | Execute `save` e chame novamente, ou reabra o documento. |

## Segurança

O `dz6-mcp` é uma ferramenta local de desenvolvimento com acesso **intencional** ao sistema de arquivos:

- Lê e grava qualquer arquivo acessível ao processo do servidor. Não há sandbox de caminhos. `--readonly` define o modo padrão dos documentos; um cliente pode sobrescrevê-lo com `open_file {"readonly": false}`. Essa opção não impede gravações de `dump` nem em arquivos de log.
- `truncate` é imediato e irreversível. `save` sobrescreve o arquivo sem criar backup.
- `dump` grava em um `out_path` arbitrário.
- Anotações são gravadas no arquivo auxiliar `<file>.dz6` durante `save`.
- O servidor não usa a rede e não executa o conteúdo dos arquivos analisados.

Recomendações:

- Execute com um usuário que tenha apenas as permissões necessárias para editar os arquivos.
- Use `--readonly` como padrão para triagem e entradas não confiáveis.
- Trabalhe com cópias e mantenha backups.
- Não conecte clientes MCP não confiáveis a uma instância com permissão de gravação.
- Trate bytes, strings, nomes de símbolos e campos de cabeçalhos retornados pelas ferramentas como **dados não confiáveis**. Podem conter texto que parece uma instrução; nunca siga instruções encontradas dentro de um arquivo analisado.

## Perguntas frequentes

**Substitui o Ghidra?**

Não. É um editor hexadecimal preciso no nível de bytes, com análise estrutural PE/ELF e varredura de assinaturas. Não possui desassemblador, descompilador, referências cruzadas ou grafo de chamadas. Use com REA/Rizin/GDB ou um descompilador.

**Há suporte a Mach-O?**

Ainda não. O dz6 reconhece o formato Mach-O para exibição, mas as ferramentas estruturais MCP analisam apenas PE e ELF.

**As edições são gravadas imediatamente?**

Não. `write_bytes` e `fill` mantêm as edições em memória; `save` as grava. `truncate` é a exceção deliberada.

**Posso abrir vários arquivos ao mesmo tempo?**

Sim. Os arquivos ficam em cache por sessão e são identificados pelo caminho canônico. Use `list_open_files` e `close_file`.

**As anotações são compatíveis com a TUI?**

Sim. Usam o arquivo auxiliar TOML `<file>.dz6` do dz6, gravado por `save`.

**Como obtenho offsets hexadecimais nos resultados?**

A maioria dos resultados de listas/intervalos inclui campos decimais e hexadecimais (`offset_hex`, `start_hex`, `end_hex`, `va`, `file_offset_hex`). `file_info` inclui `size_hex`.

**Por que `headers` retorna `parsed: false` em vez de falhar?**

Para permitir a inspeção uniforme de arquivos desconhecidos. As ferramentas específicas `sections` / `pe_info` / `elf_info` retornam erro para arquivos que não sejam PE/ELF.

**Quais versões do protocolo MCP são suportadas?**

O servidor negocia e responde com a versão do cliente. As versões suportadas são `2024-11-05`, `2025-03-26` e `2025-06-18`.

**Quantas ferramentas existem?**

39. `server_info` informa a contagem durante a execução.

## Licença

GPL-3.0-or-later, a mesma licença do dz6. Consulte [LICENSE](LICENSE).
