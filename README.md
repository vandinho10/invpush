# invpush — Agente de inventário de máquinas

**invpush** é um utilitário de linha de comando em **C++17** que coleta o
inventário de rede de uma máquina (interfaces, IPs, máscaras, classificação
de tipo) e envia via HTTPS para a API central (`host_inventory`). Substitui
o legado coletor em Python (`psutil` + `requests`), produzindo exatamente o
mesmo payload JSON sem dependência de interpretador.

## Destaques

- **Zero dependências em runtime**: Linux vincula `libcurl` do sistema;
  Windows gera binário **100% estático** com transporte nativo WinHTTP
  (Schannel) — nenhum DLL necessário.
- **Fidelidade total ao legado**: classificação de endereços idêntica ao
  módulo `ipaddress` do Python (privada, link-local, global, reservada),
  máscaras no mesmo formato do `psutil`, mensagens de log equivalentes.
- **Multiplataforma**: Linux x86_64 / aarch64 / arm32 e Windows amd64 / x86.
- **Seguro**: token de coleta via variável de ambiente ou flag — nunca
  compilado dentro do binário.

## Requisitos

- Compilador `g++` com suporte a **C++17**.
- POSIX: `libcurl` para desenvolvimento (`libcurl4-openssl-dev` no Debian).
- Windows (cross): `mingw-w64`.

## Compilação

```bash
make              # build de release (otimizado)
./cross.sh        # build multiplataforma -> dist/
```

Compilação manual:

```bash
g++ -std=c++17 -O2 -o invpush main.cpp invpush.cpp config.cpp -lcurl          # Linux
x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o invpush.exe \
  main.cpp invpush.cpp config.cpp -lwinhttp -liphlpapi -lws2_32               # Windows
```

## Verificação, Testes e Sanitizers

```bash
make check        # warnings tratados como erro (-Werror)
make test         # suíte table-driven (JSON, IPs, classificação, payload, args)
make sanitize     # AddressSanitizer + UndefinedBehaviorSanitizer
```

## Uso

```bash
INVENTORY_COLLECTION_API_TOKEN=... ./invpush            # envio normal
./invpush --print                                       # mostra payload e sai
./invpush --url https://api.vandinho.com.br/api/inventory/report --token ...
./invpush --debug --maquina NB-01                       # dumpa payload/resposta
```

Opções principais:

| Opção | Padrão | Descrição |
|---|---|---|
| `--url` | `https://api.vandinho.com.br/api/inventory/report` | Endpoint de ingestão |
| `--token` | `$INVENTORY_COLLECTION_API_TOKEN` | Bearer token de coleta |
| `--maquina` | hostname do sistema | Sobrescreve o nome reportado |
| `--timeout` | `10` (s) | Timeout do POST |
| `--janela-boot` | `300` (s) | Uptime menor que isto → `"modo": "boot"` |
| `--ip-publico` | consulta api.ipify.org | Fixa o IP público de saída |
| `--print` | — | Imprime o JSON coletado sem enviar |
| `--nao-verificar-tls` | verificação ativa | Desabilita validade do certificado |
| `-d/--debug`, `-q/--quiet` | — | Verbosidade |

## Configuração Persistente

Salve suas preferências uma vez e rode `invpush` sem flags — no estilo do
`git config`.

```bash
# Global (padrão): vale para qualquer diretório
invpush config set url https://api.vandinho.com.br/api/inventory/report
invpush config set token <INVENTORY_COLLECTION_API_TOKEN>
invpush config set janela-boot 600
invpush config list                 # visão efetiva com origem [global]/[local]
invpush config get timeout          # imprime os valores da chave
invpush config unset token          # remove a chave
invpush config path                 # mostra os caminhos global e local

# Local: grava ./.invpush.conf no projeto atual (commitável)
invpush config --local set maquina NB-01
```

**Precedência:** linha de comando > `.invpush.conf` local > config global >
variáveis de ambiente (`INVENTORY_API_URL`, `INVENTORY_COLLECTION_API_TOKEN`) >
padrões. Opções não informadas na CLI são preenchidas pela config — adotar a
config não quebra deploys existentes baseados em env.

Chaves aceitas: `url`, `token`, `maquina`, `ip-publico`, `timeout`,
`janela-boot`, `verificar-tls`. O token é gravado em texto puro (mesmo modelo
do `git credentials`) — proteja o arquivo com permissões adequadas.

Formato do arquivo (`chave=valor`, uma linha por valor):

```ini
# ~/.config/invpush/config
url=https://api.vandinho.com.br/api/inventory/report
token=<INVENTORY_COLLECTION_API_TOKEN>
timeout=10
```

## Payload enviado

```json
{
  "maquina": "NB-01",
  "ip_publico_saida": "203.0.113.42",
  "interfaces": {
    "eth0": [
      {"ip": "192.168.0.50", "versao": "IPv4", "tipo": "Privado (LAN)",
       "mascara": "255.255.255.0"}
    ]
  },
  "modo": "normal"
}
```

Valores de `tipo`: `Privado (LAN)`, `Link-Local (Auto-config)`,
`Público (Internet)`, `Reservado/Outro`, `Loopback (Interno)` (não enviada),
`Inválido`.

## Agendamento

Linux (cron):

```cron
*/15 * * * * INVENTORY_COLLECTION_API_TOKEN=... /usr/local/bin/invpush >> /var/log/invpush.log 2>&1
```

Windows (Agendador de Tarefas): aponte a ação para `invpush.exe` com as
variáveis de ambiente definidas na conta de serviço.

## Atualização

```bash
invpush update check   # 0 = atualizado, 2 = há versão nova, 1 = erro
invpush update         # pergunta antes de instalar
invpush update --quiet # sem perguntas; usado pelo invpush-update.timer
```

O binário só é trocado depois de conferir o SHA256 contra o `SHA256SUMS` da
release (release sem esse arquivo é recusada); o anterior fica em
`invpush.old` e volta sozinho se o novo não responder a `--version`.
`scripts/install.sh` instala em `~/.local/bin` e cria o timer diário.
`INVPUSH_UPDATE_REPO=owner/repo` troca a origem.

> A API de releases só responde sem autenticação para repositórios públicos.
> Enquanto este repositório for privado, `invpush update` retorna `HTTP 404`.

## Documentação

Detalhes técnicos, arquitetura e contrato da API: [docs/README.md](docs/README.md).

