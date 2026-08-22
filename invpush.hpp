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

#include <map>
#include <string>
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

} // namespace invpush

#endif // INVPUSH_HPP
