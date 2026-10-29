// invpush — Agente de envio de inventário de máquinas para a API central.
//
// Substitui o coletor legado em Python (psutil + requests -> get_put.php),
// mantendo o mesmo contrato de payload e as mesmas classificações de endereço.
// Destino atual: POST {url} com Authorization: Bearer <INVENTORY_COLLECTION_API_TOKEN>
// (módulo host_inventory da API Go).
//
// Payload (compatível com o legado):
//   {"maquina":"<host>",
//    "ip_publico_saida":"<api.ipify.org|Indisponível>",
//    "interfaces":{"<if>":[{"ip":"..","versao":"IPv4","tipo":"..","mascara":".."}]},
//    "modo":"normal"}   // extensão do contrato Go; ausente no legado
#ifndef INVPUSH_HPP
#define INVPUSH_HPP

#include <filesystem>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace invpush
{

// Versão do agente (injetada pelo Makefile via -DINVPUSH_VERSION).
#ifndef INVPUSH_VERSION
#define INVPUSH_VERSION "dev"
#endif

// Endpoint padrão de ingestão (pode ser sobrescrito por flag/env).
extern const char *const kUrlPadrao;

// Endereco é um endereço IP reportado em uma interface da máquina.
struct Endereco
{
    std::string ip;
    std::string versao;   // "IPv4" | "IPv6"
    std::string tipo;     // mesmos rótulos do coletor legado em Python
    std::string mascara;  // dotted quad (v4) ou forma expandida (v6)
};

// Mapa interface -> endereços reportados.
using Ifaces = std::map<std::string, std::vector<Endereco>>;

// Configuração resolvida: flags > variáveis de ambiente > padrões.
struct Config
{
    std::string url;      // env INVENTORY_API_URL
    std::string token;    // env INVENTORY_COLLECTION_API_TOKEN
    std::string maquina;  // vazio = hostname do sistema
    std::string ip_publico_fixo; // --ip-publico: pula consulta ao ipify
    int timeout_s = 10;   // timeout do POST (legado usava 10 s)
    int janela_boot_s = 300; // uptime < janela => modo "boot"
    bool verificar_tls = true;
    bool imprimir = false;   // --print: mostra o payload e sai sem enviar
    bool silencioso = false; // -q/--quiet
    bool debug = false;      // -d/--debug: dumpa payload/resposta crua
    bool ajuda = false;
    bool versao = false;

    // Opções efetivamente fornecidas na linha de comando (precedência
    // CLI > config local > config global > env > padrões).
    bool cli_url = false;
    bool cli_token = false;
    bool cli_maquina = false;
    bool cli_timeout = false;
    bool cli_janela_boot = false;
    bool cli_ip_publico = false;
    bool cli_verificar_tls = false;
};

// Resultado de uma requisição HTTP.
struct ResultadoEnvio
{
    bool ok = false;
    long status_http = 0;
    std::string corpo;
    std::string erro;
};

// ---- CLI ----
bool parse_args(int argc, char *argv[], Config &cfg);
void apply_env(Config &cfg);
void print_help(const char *prog);

// ---- Coleta ----
std::string hostname_do_sistema();
long uptime_segundos();
Ifaces coletar_interfaces();
std::string detectar_modo(long uptime_s, int janela_boot_s);

// Consulta o IP público de saída (api.ipify.org, 3 s); falha => "Indisponível".
std::string obter_ip_publico();

// GET HTTPS com TLS verificado (usado pelo `invpush update`); falha => vazio + erro.
std::string http_get(const std::string &url, int timeout_s, std::string &erro);

// Log com timestamp no formato do legado: [YYYY-MM-DD HH:MM:SS] mensagem.
std::string agora_log();
void log_info(const std::string &msg);
void log_debug(const Config &cfg, const std::string &msg);
void log_erro(const std::string &msg);

// ---- Funções puras (cobertas pela suíte de testes) ----
std::string json_escape(const std::string &s);
std::string mascara_ipv4(int prefixo);
std::string mascara_ipv6(int prefixo);
bool parse_ipv4(const std::string &s, unsigned char octetos[4]);
bool prefixo_de_mascara(const std::string &mascara, int &prefixo);
bool expandir_ipv6(const std::string &ip, unsigned short grupos[8]);

// Classificação idêntica ao legado (ordem elif de ipaddress):
// loopback -> "Loopback (Interno)"; private -> "Privado (LAN)";
// link-local -> "Link-Local (Auto-config)"; global -> "Público (Internet)";
// caso contrário -> "Reservado/Outro".
std::string classificar_ipv4(const std::string &ip);
std::string classificar_ipv6(const std::string &ip);

// ---- Payload e envio ----
std::string montar_payload(const std::string &maquina, const Ifaces &ifaces,
                           const std::string &modo,
                           const std::string &ip_publico_saida,
                           bool incluir_modo = true);
ResultadoEnvio enviar(const Config &cfg, const std::string &payload);

// Orquestração principal (retorna código de saída do processo).
int run(Config cfg);

// ------------------------- configuração persistente ------------------------

// Nível de configuração: conjunto ordenado de chaves com valores múltiplos.
struct NivelConfig
{
    std::vector<std::pair<std::string, std::vector<std::string>>> entradas;

    bool vazia() const;
    const std::vector<std::string> *busca(const std::string &chave) const;
    void define(const std::string &chave, std::vector<std::string> valores);
    void acrescenta(const std::string &chave, const std::vector<std::string> &valores);
    void remove(const std::string &chave);
};

// Chaves aceitas no arquivo de configuração.
bool chave_valida(const std::string &chave);

// Converte "true/1/sim/yes/on" (e negações) para bool; fora disso usa o padrão.
bool valor_bool(const std::string &valor, bool padrao);

// Global: $INVPUSH_CONFIG_HOME/invpush/config (teste/sandbox) ou o diretório
// de config do usuário ($XDG_CONFIG_HOME|~/.config; %APPDATA% no Windows).
std::filesystem::path caminho_config_global();

// Local: primeiro arquivo `.invpush.conf` a partir de `inicio` subindo até a
// raiz. Retorna caminho vazio se não houver.
std::filesystem::path descobrir_config_local(const std::filesystem::path &inicio);

NivelConfig carregar_nivel(const std::filesystem::path &arquivo);
bool salvar_nivel(const std::filesystem::path &arquivo, const NivelConfig &nivel);

// Local sobrepõe global por chave inteira (estilo git).
NivelConfig mesclar_niveis(const NivelConfig &global, const NivelConfig &local);

// Preenche em `cfg` as opções NÃO fornecidas na CLI (aplicar após apply_env:
// config vence env; CLI vence tudo via flags cli_*).
void aplicar_config(Config &cfg, const NivelConfig &efetivo);

// Subcomando `invpush config [get|set|add|unset|list|path]` — retorna código
// de saída. Escrita via --global (padrão) ou --local.
int comando_config(int argc, char *argv[]);

} // namespace invpush

#endif // INVPUSH_HPP
