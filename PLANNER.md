# PLANNER — invpush

## Objetivo

Substituir o coletor Python de inventário (`psutil` + `requests`) por um
agente C++17 leve, multiplataforma e sem dependência de interpretador,
enviando o mesmo payload à API central `host_inventory`.

## Fases

### 1. Contrato e fidelidade (concluída)
- Replicar byte a byte a estrutura JSON do legado.
- Classificação idêntica ao módulo `ipaddress` (ordem elif, faixas privadas,
  CGNAT, TEST-NETs).
- Máscaras no formato psutil; zona IPv6 removida.

### 2. Implementação (concluída)
- Coleta POSIX/Windows, classificador próprio testável, payload manual.
- Transportes: libcurl (POSIX) e WinHTTP estático (Windows).
- CLI + env; modo `boot` por janela de uptime como extensão.

### 3. Qualidade (concluída)
- Suíte table-driven das funções puras; sanitizers ASan+UBSan; `-Werror`.

### 4. Distribuição (em andamento)
- Build nativo ARM64 no servidor + cross Windows via mingw-w64.
- CI release para linux x86_64/aarch64/arm32 + windows amd64/x86.

### 5. Rollout
- Instalar nos servidores Linux (cron) e desktops Windows (Agendador),
- Desativar os jobs do script Python após validação paralela.

## Critérios de aceite

- `make check/test/sanitize` limpos.
- Payload `--print` idêntico ao do script Python na mesma máquina.
- POST real aceito pela API (HTTP 200, host visível na página Máquinas).
- Binário Windows roda em máquina limpa sem instalar nada.
