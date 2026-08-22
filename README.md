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
g++ -std=c++17 -O2 -o invpush main.cpp invpush.cpp -lcurl          # Linux
x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o invpush.exe \
  main.cpp invpush.cpp -lwinhttp -liphlpapi -lws2_32               # Windows
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

## Documentação

Detalhes técnicos, arquitetura e contrato da API: [docs/README.md](docs/README.md).

