# Changelog — invpush

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

## [Unreleased]

## [1.2.0] - 2026-10-29

### Adicionado

- **`invpush update`**: autoatualização pela última release do GitHub
  (`update check` retorna 0/2/1). SHA256 obrigatório contra o `SHA256SUMS` da
  release, backup `.old` e rollback automático se o novo binário não
  responder a `--version`. Módulo `selfupdate` compartilhado com getip e
  ddns_manager.
- `http_get()` público (libcurl/WinHTTP, TLS verificado); `obter_ip_publico()`
  passa a usá-lo no Windows.
- `scripts/install.sh`: instala em `~/.local/bin` conferindo o `SHA256SUMS` e
  cria o `invpush-update.timer` (diário).
- CI: a release publica `SHA256SUMS`.

### Alterado

- `make install` instala em `~/.local/bin` por padrão (`BINDIR` muda o destino).
- Builds Windows com `-Wl,--no-insert-timestamp`, para hashes reprodutíveis.

## [1.1.0] - 2026-08-22

### Adicionado

- **Configuração persistente** (estilo `git config`): subcomando `invpush config`
  com verbos `list` (padrão), `get`, `set`, `add`, `unset` e `path`, escopos
  `--global` (padrão) e `--local`.
- Dois níveis de arquivo: global em
  `$XDG_CONFIG_HOME/invpush/config` (`%APPDATA%\invpush\config.txt` no Windows)
  e local `.invpush.conf` descoberto subindo a hierarquia de diretórios a partir
  do cwd (commitável por design; oculto também no Windows via atributo hidden).
- Precedência: **CLI > local > global > env (`INVENTORY_API_URL`,
  `INVENTORY_COLLECTION_API_TOKEN`) > padrões**. Opções não fornecidas na CLI
  são preenchidas pela config, que por sua vez vence o ambiente — adoção
  progressiva sem quebrar deploys existentes baseados em env.
- Chaves suportadas: `url`, `token`, `maquina`, `ip-publico`, `timeout`,
  `janela-boot`, `verificar-tls`. O token fica em texto puro no arquivo
  (mesmo modelo do `git credentials`); aviso incluído no cabeçalho gerado.
- Gravação atômica (tmp + rename), formato `chave=valor` (uma linha por valor,
  comentários com `#`), avisos para linhas/chaves/valores numéricos inválidos.
- Variável `INVPUSH_CONFIG_HOME` para redirecionar o nível global (sandbox/testes).
- 12 novos testes (roundtrip, precedência CLI×config, walk-up, ciclo
  set→get→unset, `--local`, timeout/janela inválidos etc.).

### Alterado

- Versão do binário: `1.1.0`.

## [1.0.0] - 2026-08-21

### Added

- Coletor de inventário em C++17 que substitui o agente Python legado
  (`psutil` + `requests`): mesmas interfaces, classificação, máscaras e
  formato de payload enviados a `host_inventory`.
- Classificação de endereços fiel ao módulo `ipaddress` do Python
  (ordem elif preservada, incluindo as peculiaridades de 169.254/16,
  CGNAT 100.64/10 e TEST-NETs).
- Campo `modo` (`boot` quando uptime < janela configurável, padrão 300 s).
- Transporte duplo: libcurl em POSIX; WinHTTP nativo com binário 100%
  estático no Windows.
- CLI completa: `--url`, `--token`, `--maquina`, `--timeout`,
  `--janela-boot`, `--ip-publico`, `--print`, `--nao-verificar-tls`,
  `--debug`, `--quiet`, `--help`, `--version`; configuração via env
  `INVENTORY_API_URL` / `INVENTORY_COLLECTION_API_TOKEN`.
- Suíte table-driven (`make test`) e build sanitizado (`make sanitize`);
  verificação estática com `-Werror` (`make check`).
- Construtor multiplataforma `cross.sh` e workflow de release com matriz
  linux x86_64/aarch64/arm32 + windows amd64/x86.
