# invpush — Documentação técnica

## Arquitetura

```
main.cpp        CLI (parse de argumentos, --help/--version) -> invpush::run
invpush.hpp/cpp Coleta + classificação + payload + transporte
  coleta        POSIX getifaddrs | Windows GetAdaptersAddresses
  classificação Réplica do módulo ipaddress do Python (ordem elif fiel)
  payload       JSON gerado manualmente (escape próprio, sem dependências)
  transporte    libcurl (POSIX) | WinHTTP + Schannel (Windows)
```

Sem dependências externas além do transporte: todo o parsing de IP,
máscara e geração de JSON é implementado no próprio projeto e coberto por
testes unitários.

## Contrato com a API (`host_inventory`)

`POST {url}` com header `Authorization: Bearer <INVENTORY_COLLECTION_API_TOKEN>`:

```json
{
  "maquina": "string*",
  "ip_publico_saida": "string",
  "interfaces": {
    "<nome>": [{"ip", "versao": "IPv4|IPv6", "tipo", "mascara"}]
  },
  "modo": "boot|normal"
}
```

Respostas: `200 {"status":"success","mensagem":"Dados processados","id":"<uuid>"}`
ou `4xx/5xx` com `{"detail": ...}`. O campo `modo` é uma extensão deste agente
(aceita `null`/ausente no servidor); os demais campos reproduzem o contrato do
coletor Python legado. O servidor grava `ip_publico_saida` **verbatim** — a
obtenção do IP público é responsabilidade do cliente (api.ipify.org, timeout
3 s, fallback `"Indisponível"`).

## Classificação de endereços (fidelidade ao legado)

Ordem de decisão idêntica ao script Python original:

1. Loopback → descartada.
2. `is_private` → `Privado (LAN)` — inclui 10/8, 172.16/12, 192.168/16,
   169.254/16, TEST-NETs (192.0.2/24, 198.51.100/24, 203.0.113/24), CGNAT
   não entra aqui; em IPv6: fe80::/10, fc00::/7, 2001:db8::/32.
3. `is_link_local` → `Link-Local (Auto-config)` (inacessível em IPv4 porque
   169.254/16 já é private; preservado por fidelidade).
4. `is_global` → `Público (Internet)` — CGNAT 100.64/10 fica de fora.
5. Resto → `Reservado/Outro`. Parse inválido → `Inválido`.
6. IPv6 mapeado `::ffff:a.b.c.d` delega para as regras IPv4.

Máscaras: IPv4 em dotted quad; IPv6 na forma expandida do `psutil`
(`ffff:ffff:ffff:ffff::`). Sufixo de zona (`%eth0`) removido.

## Detecção de modo

Uptime < `--janela-boot` (padrão 300 s) → `"modo": "boot"`; caso contrário
`normal`. Uptime indisponível → `normal`. Fontes: `/proc/uptime` (Linux),
`GetTickCount64` (Windows).

## Segurança

- Token **nunca** embutido no binário: vem de env ou flag.
- TLS verificado por padrão (`--nao-verificar-tls` apenas para laboratório).
- Somente leitura de dados da máquina; nenhuma operação de escrita local
  além do log opcional.

## Multiplataforma

| Alvo | Toolchain | Transporte | Linkagem |
|---|---|---|---|
| linux x86_64 / aarch64 / arm32 | g++ (container debian:bookworm-slim) | libcurl dinâmico | `-lcurl` |
| windows amd64 / x86 | mingw-w64 cross | WinHTTP nativo | 100% estático |

`./cross.sh orquestra tudo em dist/`; o CI (`.github/workflows/release.yml`)
reproduz a matriz em tags `v*` e publica os artefatos na release.

## Limitações conhecidas

- Windows: interfaces desativadas são omitidas (mesmo comportamento do
  `psutil`); nomes de adaptador são os friendly names.
- Não há cache offline: se a API estiver inacessível o ciclo falha e o
  scheduler tenta novamente no próximo disparo.
