# Engenharia reversa do demo em assembly com dz6-mcp

[English](assembly-demo.md) | **Português (Brasil)** | [README principal](../README.pt-BR.md)

Este laboratório vai da conexão de um cliente MCP à identificação e alteração de uma flag de acesso de um byte. Você pode inspecionar o mesmo arquivo no editor de terminal dz6 e usar um desassemblador para explicar suas instruções. O verificador incluído exercita as 39 ferramentas MCP em cópias descartáveis.

## O que está incluído

| Arquivo | Finalidade |
| --- | --- |
| [`demo.s`](../examples/assembly/demo.s) | Assembly x86-64 comentado, com sintaxe Intel do GNU assembler. |
| [`demo.elf`](../examples/assembly/bin/demo.elf) | Executável Linux sem libc nem dependências dinâmicas. Inicialmente imprime `Access denied!`. |
| [`demo.exe`](../examples/assembly/bin/demo.exe) | Arquivo PE32+ para inspeção, com símbolos exportados. Não é destinado à execução no Windows. |
| [`manifest.json`](../examples/assembly/bin/manifest.json) | Offsets de arquivo, endereços virtuais e seções dos pontos de referência nomeados nos dois arquivos. |
| [`build.py`](../examples/assembly/build.py) | Recompila os dois arquivos e seu manifesto usando GNU binutils. |
| [`verify.py`](../examples/assembly/verify.py) | Controla o servidor MCP real via stdio, verifica resultados e confirma a cobertura de todas as ferramentas anunciadas. |

O ELF usa apenas as chamadas de sistema Linux `write` e `exit`. Ele lê `demo_gate`: zero seleciona a mensagem de acesso negado, enquanto um valor diferente de zero seleciona a mensagem de sucesso. Não solicita senha. O PE compartilha a organização dos dados e a rotina de leitura da flag, mas não inclui as chamadas de sistema Linux.

Os arquivos contêm strings UTF-8, Latin-1, UTF-16LE e UTF-16BE; inteiros com e sem sinal; assinaturas nomeadas; uma sequência crescente de 256 bytes; uma região preenchida com zeros; uma área de NOPs; e armazenamento `.bss` sem bytes correspondentes no arquivo.

São arquivos didáticos pequenos, sem exemplos de todos os diretórios opcionais de executáveis. O PE possui exportações, mas não importa APIs e não contém PDB, callbacks TLS, recursos ou certificado. O ELF estático não possui interpretador, bibliotecas NEEDED nem tabela de símbolos dinâmicos. Esses metadados estarão ausentes ou vazios. Consulte a [referência das ferramentas](../README.pt-BR.md#referência-das-ferramentas) para conhecer todos os recursos.

## 1. Prepare as ferramentas e as cópias de trabalho

Primeiro siga os [requisitos de compilação](../README.pt-BR.md#requisitos) para preparar a biblioteca dz6 com o patch e compilar o servidor MCP:

```sh
cargo build --locked
```

Os arquivos pré-compilados já podem ser inspecionados. Para recompilá-los, são necessários Python 3 e as ferramentas GNU `as`, `ld`, `nm` e `objdump`. O vinculador precisa suportar `elf_x86_64` e `i386pep`, como o GNU binutils do Ubuntu:

```sh
ld -V
python3 examples/assembly/build.py
```

A recompilação atualiza `manifest.json`; os offsets podem mudar com outra versão do vinculador. Os números deste guia correspondem aos binários incluídos. Consulte o manifesto ou descubra os offsets pelo MCP antes de alterar um arquivo recompilado.

Na raiz do repositório, crie cópias de trabalho:

```sh
mkdir -p /tmp/dz6-mcp-demo
cp examples/assembly/bin/demo.elf /tmp/dz6-mcp-demo/demo.elf
cp examples/assembly/bin/demo.exe /tmp/dz6-mcp-demo/demo.exe
chmod u+x /tmp/dz6-mcp-demo/demo.elf
```

Estes comandos são para Linux. A execução nativa exige Linux x86-64. A inspeção pelo servidor MCP não executa nenhum dos arquivos. Preserve os originais em `examples/assembly/bin` durante o laboratório. Para reiniciar o exercício, feche os documentos, copie novamente os arquivos e remova os antigos auxiliares `.dz6` das cópias de trabalho caso também queira reiniciar as anotações.

No Linux x86-64, confira o comportamento original antes de abrir o arquivo para gravação:

```sh
/tmp/dz6-mcp-demo/demo.elf
# Access denied!
```

## 2. Conecte um cliente MCP

Use a [configuração apropriada ao seu cliente](../README.pt-BR.md#configuração-dos-clientes). Por exemplo, substitua o comando abaixo pelo caminho absoluto da sua compilação:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/absolute/path/to/dz6-mcp/target/debug/dz6-mcp",
      "args": ["--readonly", "-v"]
    }
  }
}
```

Reconecte o cliente e peça:

> Use as ferramentas MCP do dz6 para inspecionar `/tmp/dz6-mcp-demo/demo.elf`. Comece com server_info, file_info, headers, sections e symbols. Encontre check_gate e demo_gate, explique a diferença entre um endereço virtual e um offset de arquivo e mostre os bytes de ambos. Mantenha o arquivo em modo somente leitura até eu pedir para alterá-lo.

`--readonly` define o modo padrão de abertura, sem impor uma sandbox. Uma chamada posterior de `open_file` com `readonly: false` habilita a parte de edição deste laboratório.

Os blocos abaixo mostram **nomes de ferramentas e argumentos JSON**, não comandos de shell. Peça ao cliente MCP para fazer essas chamadas. Ele pode exibir os nomes com um prefixo, como `mcp__dz6__`.

## 3. Identifique o formato e localize a flag

```text
server_info     {}
open_file       {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":true}
list_open_files {}
file_info       {"path":"/tmp/dz6-mcp-demo/demo.elf"}
headers         {"path":"/tmp/dz6-mcp-demo/demo.elf"}
sections        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
elf_info        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
symbols         {"path":"/tmp/dz6-mcp-demo/demo.elf","name_regex":"^(_start|check_gate|demo_gate)$"}
```

Resultados esperados: ELF64, x86-64, ponto de entrada em `.text`, constantes legíveis em `.rodata`, flag gravável em `.data` e região `.bss`. `server_info` informa 39 ferramentas. `elf_info` mostra o build-id GNU; nenhum interpretador dinâmico é necessário.

Pontos de referência do ELF incluído:

| Símbolo | Offset de arquivo (decimal) | VA | Significado |
| --- | --- | --- | --- |
| `_start` | 4096 | `0x401000` | Ponto de entrada. |
| `check_gate` | 4152 | `0x401038` | Lê o byte da flag em EAX e retorna. |
| `patch_pad` | 4160 | `0x401040` | 16 bytes NOP fora do caminho executado. |
| `demo_magic` | 8192 | `0x402000` | `DZ6DEMO` seguido de NUL. |
| `number_le` | 8200 | `0x402008` | `0x12345678`. |
| `signed_value` | 8204 | `0x40200c` | Inteiro de 32 bits com sinal, `-42`. |
| `signature_lab` | 8351 | `0x40209f` | Bytes conhecidos para buscas de padrões. |
| `entropy_ramp` | 8363 | `0x4020ab` | Todos os valores de byte de 0 a 255. |
| `zero_pad` | 8619 | `0x4021ab` | 256 bytes zero. |
| `demo_gate` | 8875 | `0x4032ab` | Inicialmente `00`; altere para `01`. |

Confirme o mapeamento nos dois sentidos:

```text
address_translate {"path":"/tmp/dz6-mcp-demo/demo.elf","address":"0x4032ab"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
read_at_address   {"path":"/tmp/dz6-mcp-demo/demo.elf","address":"0x401038","length":8}
read_bytes        {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"length":1}
```

A flag corresponde ao offset 8875 e seu byte é `00`. `scratch_buffer` fica em `.bss`, portanto possui endereço virtual, mas não tem bytes correspondentes para leitura no arquivo.

## 4. Explique as instruções com um desassemblador

O servidor MCP fornece bytes exatos e estruturas. Use GNU objdump para visualizar as instruções:

```sh
objdump -d -Mintel /tmp/dz6-mcp-demo/demo.elf
```

Em `_start`, acompanhe `call check_gate`, `test eax,eax` e o salto condicional. Em `check_gate`, identifique o `movzx` relativo a RIP que lê `demo_gate`, seguido de `ret`. O valor retornado seleciona uma das duas mensagens. Alterar o byte de dados basta para mudar o resultado, sem substituir uma instrução.

Se seu assistente tiver REA disponível, você também pode pedir que inspecione a mesma cópia de trabalho com Rizin ou objdump e depois usar dz6-mcp para confirmar offsets e bytes. REA é opcional; este laboratório não exige serviço externo de análise.

## 5. Leia números e strings

```text
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8200,"size":4,"endian":"little"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8200,"size":4,"endian":"big"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8204,"size":4,"signed":true}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8208,"encoding":"utf8"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8234,"encoding":"latin1"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8238,"encoding":"utf16le"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8246,"encoding":"utf16be"}
strings     {"path":"/tmp/dz6-mcp-demo/demo.elf","regex":"DEMO_TAG|Access","max":20}
```

A leitura little endian produz `305419896`; a leitura dos mesmos bytes como big endian produz `2018915346`. O valor com sinal é `-42`. A primeira string é `Hello, dz6! Olá, Brasil!`; as outras três codificações resultam em `Olá`. `strings` encontra sequências ASCII imprimíveis, então use `read_string` para os exercícios com outras codificações.

## 6. Faça buscas e varreduras de assinaturas

```text
goto       {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8192}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DZ6DEMO"}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"findme","ignore_case":true,"offset":0}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEMO_TAG:","direction":"backward"}
search_all {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEMO_TAG:","max":10}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEAD????","mode":"hex","offset":8351}
```

Existem três strings `DEMO_TAG:`. `goto` define o cursor padrão da busca para a frente. Buscas para trás retornam offsets absolutos em ordem decrescente. Experimente `next: true` para ignorar a ocorrência atual e `wrapscan: true` para continuar uma chamada de `search` ao atingir o fim do arquivo.

Chame `pattern_scan` com este objeto:

```json
{
  "path": "/tmp/dz6-mcp-demo/demo.elf",
  "offset": 8192,
  "length": 171,
  "context": 4,
  "patterns": [
    {"name":"literal","pattern":"DEADBEEF"},
    {"name":"nibble","pattern":"A?5A"},
    {"name":"range","pattern":"[A0-AF]5A"},
    {"name":"gap","pattern":"5A{2}BB"},
    {"name":"alternative","pattern":"(DEAD|BEEF)"},
    {"name":"mask","pattern":"A050:F0F0"},
    {"name":"overlap","pattern":"AAAA"},
    {"name":"text","pattern":"DEMO_TAG:","mode":"text"}
  ]
}
```

Todos os padrões nomeados encontram ocorrências. `AAAA` encontra duas ocorrências sobrepostas nos três bytes `AA`. A máscara verifica bits selecionados, e o intervalo consome dois bytes arbitrários. Repita com `first_only: true` ou um `max` pequeno para observar os limites dos resultados.

## 7. Compare a entropia e extraia dados

```text
analyze {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8363,"length":256}
analyze {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8619,"length":256}
dump    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8192,"length":8,"out_path":"/tmp/dz6-mcp-demo/extracted.bin"}
```

A sequência crescente tem entropia de 8 bits/byte e 256 valores distintos. A região de zeros tem entropia 0. Entropia alta, isoladamente, não comprova criptografia: esta sequência é inteiramente previsível. O arquivo extraído contém `DZ6DEMO` e NUL. `dump` grava o destino mesmo quando o documento de origem está em modo somente leitura.

## 8. Anote as descobertas

Habilite a gravação na cópia de trabalho antes de salvar as anotações:

```text
open_file     {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":false}
comment_set   {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"comment":"Access flag: 0=deny, 1=grant"}
comments_list {"path":"/tmp/dz6-mcp-demo/demo.elf"}
bookmark_add  {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
bookmarks_list {"path":"/tmp/dz6-mcp-demo/demo.elf"}
block_add     {"path":"/tmp/dz6-mcp-demo/demo.elf","start":8351,"end":8362,"bg_color":3368601}
blocks_list   {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save          {"path":"/tmp/dz6-mcp-demo/demo.elf"}
```

Confirme `database_saved: true`. As anotações ficam em `/tmp/dz6-mcp-demo/demo.elf.dz6`, compartilhado com a TUI do dz6. Se o salvamento do banco de dados estiver desabilitado na sua configuração do dz6, habilite-o antes de continuar.

## 9. Pratique desfazer e depois altere a flag

Primeiro preencha quatro bytes da área de NOPs não utilizada e desfaça essas quatro edições de bytes:

```text
fill       {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4,"kind":"zero"}
read_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4}
undo       {"path":"/tmp/dz6-mcp-demo/demo.elf","steps":4}
read_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4}
```

Os bytes voltam a `90 90 90 90`. `steps` conta edições de bytes, não chamadas de ferramentas.

Agora altere a flag:

```text
write_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"data":"01"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"size":1}
file_info   {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file  {"path":"/tmp/dz6-mcp-demo/demo.elf"}
```

Antes de `save`, as leituras pelo MCP mostram `1`, mas o arquivo no disco ainda contém `0`. Após salvar, `pending_changes` é zero. Feche o documento gravável antes de executar, ou o Linux poderá retornar `Text file busy`:

```sh
/tmp/dz6-mcp-demo/demo.elf
# Access granted
```

Peça ao assistente:

> Explique por que esta alteração de um byte de dados muda o resultado do salto. Mostre a flag salva, as instruções de check_gate e as strings de saída. Diferencie as evidências do arquivo da sua interpretação do código.

## 10. Abra o mesmo arquivo no dz6

Se necessário, compile o editor de terminal a partir do checkout vizinho com o patch:

```sh
cargo build --manifest-path ../dz6/Cargo.toml --bin dz6
../dz6/target/debug/dz6 -r /tmp/dz6-mcp-demo/demo.elf
```

Se sua configuração do Cargo usar um diretório de compilação compartilhado, ajuste o caminho do executável. No dz6:

- Digite `:8875t` e Enter para ir ao offset decimal 8875, ou `:22ab` para hexadecimal `0x22ab`.
- Inspecione o byte `01` e o comentário salvo na posição da flag.
- Pressione `Tab` para alternar entre Hex, Text e Headers.
- Use `/` para buscar `Access`; `Tab` durante a busca alterna entre texto e hexadecimal.
- Digite `:q` para sair.

O comando de navegação decimal é `:8875t`. Os offsets do dz6 são hexadecimais por padrão, enquanto os offsets numéricos do MCP são decimais. Mantenha a inspeção na TUI em modo somente leitura e reabra o documento MCP após alterações externas para atualizar o estado em cache.

## 11. Inspecione o PE complementar

```text
open_file         {"path":"/tmp/dz6-mcp-demo/demo.exe","readonly":true}
headers           {"path":"/tmp/dz6-mcp-demo/demo.exe"}
sections          {"path":"/tmp/dz6-mcp-demo/demo.exe"}
pe_info           {"path":"/tmp/dz6-mcp-demo/demo.exe"}
symbols           {"path":"/tmp/dz6-mcp-demo/demo.exe","kind":"export","name_regex":"check_gate|demo_gate"}
symbols           {"path":"/tmp/dz6-mcp-demo/demo.exe","kind":"import"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x140001000"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x1000","kind":"rva"}
read_at_address   {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x140001000","length":16}
```

No PE incluído, ambas as conversões correspondem ao offset 1024: VA é igual à base da imagem `0x140000000` mais o RVA `0x1000`. Use as exportações PE para localizar os rótulos; `symbols` em PE não expõe a tabela de símbolos COFF. O arquivo não importa APIs. `elf_info` neste arquivo, ou `pe_info` no ELF, deve retornar um erro de formato.

## 12. Pratique limpeza e truncamento

Reabra o ELF para gravação caso queira remover anotações. Um comentário vazio remove aquele comentário:

```text
open_file       {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":false}
comment_set     {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"comment":""}
bookmark_remove {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
bookmark_clear  {"path":"/tmp/dz6-mcp-demo/demo.elf"}
block_clear     {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save            {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file      {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file      {"path":"/tmp/dz6-mcp-demo/demo.exe"}
```

Use somente o arquivo bruto extraído para praticar truncamento:

```text
open_file  {"path":"/tmp/dz6-mcp-demo/extracted.bin","readonly":false}
truncate   {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":5,"mode":"after"}
truncate   {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":3,"mode":"before"}
read_bytes {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":0,"length":3}
close_file {"path":"/tmp/dz6-mcp-demo/extracted.bin"}
```

Os tamanhos passam a 6 e depois a 3 bytes, restando `DEM` (`44 45 4D`). Essas alterações são imediatas e não podem ser desfeitas. Não trunque um executável em execução ou mapeado por outro processo.

## 13. Inspecione os logs e execute a verificação completa

```text
log_level  {"level":"debug"}
server_info {}
logs_tail  {"limit":20}
logs_clear {}
log_level  {"level":"warn"}
```

Execute a versão automatizada na raiz do repositório:

```sh
python3 examples/assembly/verify.py --server target/debug/dz6-mcp
```

Ela cria um diretório temporário, chama todas as ferramentas anunciadas por `tools/list`, verifica resultados representativos, confirma a persistência das anotações após reabrir o arquivo e remove as cópias de trabalho ao terminar. No Linux x86-64, também executa o ELF antes e depois da alteração. Use `--skip-execution` para verificar somente a inspeção. O PE nunca é executado.

Saída esperada:

```text
PASS: all 39 MCP tools; ELF/PE inspection, encodings, signatures, edits, sidecar and truncation
PASS: saved gate patch changes Linux output
```

O fluxo de CI recompila os arquivos e executa essa verificação com um servidor MCP recém-compilado. Você pode repetir os passos manuais de forma independente; o verificador não depende da sessão em `/tmp/dz6-mcp-demo`.
