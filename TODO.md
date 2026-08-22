# TODO — invpush

## Feito

- [x] Coleta POSIX (getifaddrs) e Windows (GetAdaptersAddresses)
- [x] Classificação fiel ao ipaddress do Python
- [x] Geração de payload JSON com escape próprio
- [x] Transporte libcurl (POSIX) / WinHTTP estático (Windows)
- [x] CLI completa + resolução env > flags
- [x] Detecção de modo boot/normal por uptime
- [x] Suíte de testes + sanitizers + check -Werror
- [x] cross.sh multiplataforma + release.yml

## Próximo

- [ ] Validar coleta real no servidor ARM64 e no desktop Windows
- [ ] Empacotar .deb para distribuição nos servidores Debian
- [ ] Instalação MSI/WiX ou script PowerShell para o parque Windows
- [ ] Cache offline local (spool) para envios quando a API voltar

## Ideias

- [ ] Assinatura Authenticode dos binários Windows
- [ ] Modo serviço (daemon/serviço do Windows) com timer interno
