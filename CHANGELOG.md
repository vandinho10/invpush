# Changelog — invpush

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

## [Unreleased]

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
