// invpush — implementação da coleta, montagem do payload e envio HTTP.
//
// Transporte: libcurl (POSIX) ou WinHTTP nativo (Windows/Schannel), atrás de
// enviar() e obter_ip_publico(). Nas builds Windows o binário fica 100%
// estático, sem DLLs extras. Coleta de interfaces espelha psutil.net_if_addrs
// e a classificação replica a ordem de elif do coletor legado (ipaddress).
#include "invpush.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// GetAdaptersAddresses/GAA_FLAG_* exigem NTDDI >= XP declarado antes dos headers.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winhttp.h>
#else
#include <arpa/inet.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace invpush
{

const char *const kUrlPadrao = "https://api.vandinho.com.br/api/inventory/report";

namespace
{

const char *const kIpifyUrl = "https://api.ipify.org";
constexpr int kIpifyTimeoutS = 3;

} // namespace

// ---------------------------------------------------------------- JSON utils

std::string json_escape(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20)
            {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
            {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

// Extrai o valor string bruto de uma chave simples no corpo JSON de resposta.
static std::string json_campo_string(const std::string &corpo, const char *chave)
{
    std::string agulha = "\"" + std::string(chave) + "\"";
    const auto pos = corpo.find(agulha);
    if (pos == std::string::npos) return {};
    const auto dp = corpo.find(':', pos + agulha.size());
    if (dp == std::string::npos) return {};
    auto ini = corpo.find('"', dp + 1);
    if (ini == std::string::npos) return {};
    ++ini;
    std::string out;
    for (size_t i = ini; i < corpo.size(); ++i)
    {
        if (corpo[i] == '\\' && i + 1 < corpo.size())
        {
            out += corpo[i];
            out += corpo[i + 1];
            ++i;
            continue;
        }
        if (corpo[i] == '"') break;
        out += corpo[i];
    }
    return out;
}

// ------------------------------------------------------------------- Logging

std::string agora_log()
{
    std::tm tm_buf{};
    std::time_t agora = std::time(nullptr);
#if defined(_WIN32)
    localtime_s(&tm_buf, &agora);
#else
    localtime_r(&agora, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

void log_info(const std::string &msg)
{
    std::cout << "[" << agora_log() << "] " << msg << "\n";
    std::cout.flush();
}

void log_debug(const Config &cfg, const std::string &msg)
{
    if (!cfg.debug) return;
    std::cout << "[" << agora_log() << "] [DEBUG] " << msg << "\n";
    std::cout.flush();
}

void log_erro(const std::string &msg)
{
    std::cerr << "[" << agora_log() << "] " << msg << "\n";
}

// ------------------------------------------------------------- IP utilities

bool parse_ipv4(const std::string &s, unsigned char octetos[4])
{
    int valores[4] = {-1, -1, -1, -1};
    if (std::sscanf(s.c_str(), "%d.%d.%d.%d", &valores[0], &valores[1], &valores[2], &valores[3]) != 4)
    {
        return false;
    }
    for (int i = 0; i < 4; ++i)
    {
        if (valores[i] < 0 || valores[i] > 255) return false;
        octetos[i] = static_cast<unsigned char>(valores[i]);
    }
    return true;
}

std::string mascara_ipv4(int prefixo)
{
    if (prefixo <= 0) return "0.0.0.0";
    unsigned long m = prefixo >= 32 ? 0xFFFFFFFFUL : ~(0xFFFFFFFFUL >> prefixo);
    unsigned char b[4] = {
        static_cast<unsigned char>((m >> 24) & 0xFF),
        static_cast<unsigned char>((m >> 16) & 0xFF),
        static_cast<unsigned char>((m >> 8) & 0xFF),
        static_cast<unsigned char>(m & 0xFF),
    };
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

// Forma expandida estilo psutil: grupos de uns seguidos de compressão '::'.
// Ex.: /64 -> ffff:ffff:ffff:ffff::
std::string mascara_ipv6(int prefixo)
{
    if (prefixo < 0) prefixo = 0;
    if (prefixo > 128) prefixo = 128;

    unsigned short grupos[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int bit = 0; bit < prefixo; ++bit)
    {
        grupos[bit / 16] |= static_cast<unsigned short>(0x8000 >> (bit % 16));
    }

    // Máscara é um sufixo contíguo de zeros após os grupos de uns.
    int fim_uns = 0;
    while (fim_uns < 8 && grupos[fim_uns] == 0xFFFF) ++fim_uns;

    std::string out;
    char buf[8];
    for (int i = 0; i < fim_uns; ++i)
    {
        std::snprintf(buf, sizeof(buf), "%x", grupos[i]);
        if (i > 0) out += ':';
        out += buf;
    }
    if (fim_uns < 8) out += "::";
    return out;
}

bool prefixo_de_mascara(const std::string &mascara, int &prefixo)
{
    unsigned char b[4];
    if (!parse_ipv4(mascara, b)) return false;
    unsigned long m = (static_cast<unsigned long>(b[0]) << 24) |
                      (static_cast<unsigned long>(b[1]) << 16) |
                      (static_cast<unsigned long>(b[2]) << 8) |
                      static_cast<unsigned long>(b[3]);
    bool em_uns = true;
    int bits = 0;
    for (int i = 31; i >= 0; --i)
    {
        const bool um = ((m >> i) & 1UL) != 0;
        if (um && !em_uns) return false; // máscara não contígua
        if (!um) em_uns = false;
        if (um) ++bits;
    }
    prefixo = bits;
    return true;
}

bool expandir_ipv6(const std::string &ip, unsigned short grupos[8])
{
    std::string corpo = ip;
    const auto pct = corpo.find('%'); // zona de escopo (fe80%eth0): ignorada
    if (pct != std::string::npos) corpo = corpo.substr(0, pct);

    for (int i = 0; i < 8; ++i) grupos[i] = 0;
    if (corpo.empty()) return false;

    auto grupo_valido = [](const std::string &tok, unsigned short &valor) {
        if (tok.empty() || tok.size() > 4) return false;
        for (char c : tok)
        {
            bool hexdig = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hexdig) return false;
        }
        valor = static_cast<unsigned short>(std::strtoul(tok.c_str(), nullptr, 16));
        return true;
    };

    const auto dc = corpo.find("::");
    int usados = 0;

    if (dc == std::string::npos)
    {
        int pos = 0;
        while (pos <= static_cast<int>(corpo.size()))
        {
            if (usados >= 8) return false;
            const auto sep = corpo.find(':', pos);
            std::string tok =
                sep == std::string::npos ? corpo.substr(pos) : corpo.substr(pos, sep - pos);
            unsigned short v = 0;
            if (!grupo_valido(tok, v)) return false;
            grupos[usados++] = v;
            if (sep == std::string::npos) break;
            pos = static_cast<int>(sep) + 1;
            if (sep == corpo.size() - 1) return false; // ':' final sem '::'
        }
        return usados == 8;
    }

    const std::string esq = corpo.substr(0, dc);
    const std::string dir = corpo.substr(dc + 2);

    if (!esq.empty())
    {
        int pos = 0;
        while (pos <= static_cast<int>(esq.size()))
        {
            if (usados >= 8) return false;
            const auto sep = esq.find(':', pos);
            std::string tok =
                sep == std::string::npos ? esq.substr(pos) : esq.substr(pos, sep - pos);
            unsigned short v = 0;
            if (!grupo_valido(tok, v)) return false;
            grupos[usados++] = v;
            if (sep == std::string::npos) break;
            pos = static_cast<int>(sep) + 1;
        }
    }

    int idx_dir = 7;
    if (!dir.empty())
    {
        int fim = static_cast<int>(dir.size());
        while (fim > 0)
        {
            if (idx_dir < usados) return false;
            const auto sep = dir.rfind(':', fim - 1);
            std::string tok =
                sep == std::string::npos ? dir.substr(0, fim) : dir.substr(sep + 1, fim - sep - 1);
            unsigned short v = 0;
            if (!grupo_valido(tok, v)) return false;
            grupos[idx_dir--] = v;
            if (sep == std::string::npos) break;
            fim = static_cast<int>(sep);
        }
    }
    return usados <= idx_dir + 1;
}

// Predicados que replicam os atributos do módulo ipaddress (CPython).

static bool ipv4_em_prefixo(const unsigned char o[4], unsigned a, unsigned b,
                            unsigned c, unsigned d, int bits)
{
    const unsigned ip = (static_cast<unsigned>(o[0]) << 24) |
                        (static_cast<unsigned>(o[1]) << 16) |
                        (static_cast<unsigned>(o[2]) << 8) | o[3];
    const unsigned base = (a << 24) | (b << 16) | (c << 8) | d;
    if (bits <= 0) return true;
    if (bits >= 32) return ip == base;
    const unsigned mascara = ~0U << (32 - bits);
    return (ip & mascara) == (base & mascara);
}

static bool ipv4_is_loopback(const unsigned char o[4])
{
    return ipv4_em_prefixo(o, 127, 0, 0, 0, 8);
}

static bool ipv4_is_link_local(const unsigned char o[4])
{
    return ipv4_em_prefixo(o, 169, 254, 0, 0, 16);
}

// Espelha ipaddress.IPv4Address.is_private (_private_networks).
static bool ipv4_is_private(const unsigned char o[4])
{
    return ipv4_em_prefixo(o, 0, 0, 0, 0, 8) ||
           ipv4_em_prefixo(o, 10, 0, 0, 0, 8) ||
           ipv4_em_prefixo(o, 127, 0, 0, 0, 8) ||
           ipv4_em_prefixo(o, 169, 254, 0, 0, 16) ||
           ipv4_em_prefixo(o, 172, 16, 0, 0, 12) ||
           ipv4_em_prefixo(o, 192, 0, 0, 0, 29) ||
           ipv4_em_prefixo(o, 192, 0, 0, 170, 31) ||
           ipv4_em_prefixo(o, 192, 0, 2, 0, 24) ||
           ipv4_em_prefixo(o, 192, 168, 0, 0, 16) ||
           ipv4_em_prefixo(o, 198, 18, 0, 0, 15) ||
           ipv4_em_prefixo(o, 198, 51, 100, 0, 24) ||
           ipv4_em_prefixo(o, 203, 0, 113, 0, 24) ||
           ipv4_em_prefixo(o, 240, 0, 0, 0, 4) ||
           ipv4_em_prefixo(o, 255, 255, 255, 255, 32);
}

// Espelha IPv4Address.is_global: não é CGNAT (100.64/10) nem privado.
static bool ipv4_is_global(const unsigned char o[4])
{
    return !ipv4_em_prefixo(o, 100, 64, 0, 0, 10) && !ipv4_is_private(o);
}

std::string classificar_ipv4(const std::string &ip)
{
    unsigned char o[4];
    if (!parse_ipv4(ip, o)) return "Inválido";
    if (ipv4_is_loopback(o)) return "Loopback (Interno)";
    if (ipv4_is_private(o)) return "Privado (LAN)";
    if (ipv4_is_link_local(o)) return "Link-Local (Auto-config)";
    if (ipv4_is_global(o)) return "Público (Internet)";
    return "Reservado/Outro";
}

static bool ipv6_is_private(const unsigned short g[8])
{
    // ::/128 e ::1/128
    bool todos_zero = true;
    for (int i = 0; i < 8; ++i)
    {
        if (g[i] != 0)
        {
            todos_zero = false;
            break;
        }
    }
    if (todos_zero) return true;
    // ::ffff:0:0/96 (v4-mapped)
    if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xFFFF)
    {
        unsigned char o4[4] = {static_cast<unsigned char>(g[6] >> 8),
                               static_cast<unsigned char>(g[6] & 0xFF),
                               static_cast<unsigned char>(g[7] >> 8),
                               static_cast<unsigned char>(g[7] & 0xFF)};
        return ipv4_is_private(o4);
    }
    // 2001:db8::/32 (documentação)
    if (g[0] == 0x2001 && g[1] == 0x0DB8) return true;
    // fc00::/7 (ULA)
    if ((g[0] & 0xFE00) == 0xFC00) return true;
    // fe80::/10 (link-local)
    if ((g[0] & 0xFFC0) == 0xFE80) return true;
    return false;
}

std::string classificar_ipv6(const std::string &ip)
{
    unsigned short g[8];
    if (!expandir_ipv6(ip, g)) return "Inválido";

    const bool loopback = g[7] == 1 && g[0] == 0 && g[1] == 0 && g[2] == 0 &&
                          g[3] == 0 && g[4] == 0 && g[5] == 0 && g[6] == 0;
    if (loopback) return "Loopback (Interno)";
    if (ipv6_is_private(g)) return "Privado (LAN)";
    if ((g[0] & 0xFFC0) == 0xFE80) return "Link-Local (Auto-config)";
    // IPv6 global: fora das faixas privadas/reservadas acima.
    return "Público (Internet)";
}

// ------------------------------------------------------------------- Coleta

#if defined(_WIN32)

namespace
{

std::string narrow_utf8(const wchar_t *w)
{
    if (w == nullptr) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(need > 0 ? need - 1 : 0), '\0');
    if (need > 1)
    {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), need, nullptr, nullptr);
    }
    return out;
}

std::wstring wide_utf8(const std::string &s)
{
    const int need = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(need > 0 ? need - 1 : 0), L'\0');
    if (need > 1)
    {
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), need);
    }
    return out;
}

// Garante uma única inicialização do Winsock por processo.
struct WsaGuard
{
    bool ok = false;
    WsaGuard()
    {
        WSADATA data;
        ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~WsaGuard()
    {
        if (ok) WSACleanup();
    }
};

WsaGuard &wsa()
{
    static WsaGuard g;
    return g;
}

} // namespace

std::string hostname_do_sistema()
{
    (void)wsa();
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf)) != 0) return {};
    return buf;
}

long uptime_segundos()
{
    return static_cast<long>(GetTickCount64() / 1000ULL);
}

Ifaces coletar_interfaces()
{
    (void)wsa();
    Ifaces resultado;

    ULONG tamanho = 15 * 1024;
    std::vector<char> buffer(tamanho);
    for (;;)
    {
        const ULONG rc = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &tamanho);
        if (rc == NO_ERROR) break;
        if (rc == ERROR_BUFFER_OVERFLOW)
        {
            buffer.resize(tamanho);
            continue;
        }
        return resultado; // sem dados: payload vai com interfaces vazias
    }

    auto *ad = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    for (; ad != nullptr; ad = ad->Next)
    {
        if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (ad->OperStatus != IfOperStatusUp) continue;

        const std::string nome = narrow_utf8(ad->FriendlyName);
        std::vector<Endereco> lista;

        for (auto *unicast = ad->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next)
        {
            const sockaddr *sa = unicast->Address.lpSockaddr;
            if (sa == nullptr) continue;

            Endereco e;
            char ipbuf[INET6_ADDRSTRLEN] = {0};
            if (sa->sa_family == AF_INET)
            {
                const auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
                if (inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)) == nullptr) continue;
                e.ip = ipbuf;
                e.versao = "IPv4";
                e.mascara = mascara_ipv4(static_cast<int>(unicast->OnLinkPrefixLength));
            }
            else if (sa->sa_family == AF_INET6)
            {
                const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf)) == nullptr) continue;
                e.ip = ipbuf;
                e.versao = "IPv6";
                e.mascara = mascara_ipv6(static_cast<int>(unicast->OnLinkPrefixLength));
            }
            else
            {
                continue;
            }
            e.tipo = e.versao == "IPv4" ? classificar_ipv4(e.ip) : classificar_ipv6(e.ip);
            lista.push_back(std::move(e));
        }

        if (!lista.empty()) resultado[nome] = std::move(lista);
    }
    return resultado;
}

#else // POSIX

std::string hostname_do_sistema()
{
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf)) != 0) return {};
    return buf;
}

long uptime_segundos()
{
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return static_cast<long>(si.uptime);
}

Ifaces coletar_interfaces()
{
    Ifaces resultado;
    ifaddrs *lista = nullptr;
    if (getifaddrs(&lista) != 0) return resultado;

    for (ifaddrs *ifa = lista; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;

        Endereco e;
        char ipbuf[INET6_ADDRSTRLEN] = {0};

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            const auto *sin = reinterpret_cast<const sockaddr_in *>(ifa->ifa_addr);
            if (inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)) == nullptr) continue;
            e.ip = ipbuf;
            e.versao = "IPv4";
            if (ifa->ifa_netmask != nullptr)
            {
                char maskbuf[INET_ADDRSTRLEN] = {0};
                const auto *m4 = reinterpret_cast<const sockaddr_in *>(ifa->ifa_netmask);
                if (inet_ntop(AF_INET, &m4->sin_addr, maskbuf, sizeof(maskbuf)) != nullptr)
                {
                    int prefixo = 0;
                    if (prefixo_de_mascara(maskbuf, prefixo))
                    {
                        e.mascara = mascara_ipv4(prefixo);
                    }
                }
            }
        }
        else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(ifa->ifa_addr);
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf)) == nullptr) continue;
            e.ip = ipbuf;
            e.versao = "IPv6";
            if (ifa->ifa_netmask != nullptr)
            {
                const auto *m6 = reinterpret_cast<const sockaddr_in6 *>(ifa->ifa_netmask);
                const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&m6->sin6_addr);
                int prefixo = 0;
                for (int i = 0; i < 16; ++i)
                {
                    for (int bit = 7; bit >= 0; --bit)
                    {
                        if ((bytes[i] >> bit) & 1) ++prefixo;
                    }
                }
                e.mascara = mascara_ipv6(prefixo);
            }
        }
        else
        {
            continue;
        }

        e.tipo = e.versao == "IPv4" ? classificar_ipv4(e.ip) : classificar_ipv6(e.ip);
        resultado[ifa->ifa_name].push_back(std::move(e));
    }
    freeifaddrs(lista);
    return resultado;
}

#endif

std::string detectar_modo(long uptime_s, int janela_boot_s)
{
    return uptime_s >= 0 && uptime_s < static_cast<long>(janela_boot_s) ? "boot" : "normal";
}

// ------------------------------------------------------------ Payload/envio

std::string montar_payload(const std::string &maquina, const Ifaces &ifaces,
                           const std::string &modo,
                           const std::string &ip_publico_saida,
                           bool incluir_modo)
{
    std::string out = "{\"maquina\":\"" + json_escape(maquina) + "\"";
    out += ",\"ip_publico_saida\":\"" + json_escape(ip_publico_saida) + "\"";
    out += ",\"interfaces\":{";
    bool primeiro_grupo = true;
    for (const auto &[nome, enderecos] : ifaces)
    {
        if (!primeiro_grupo) out += ',';
        primeiro_grupo = false;
        out += '"' + json_escape(nome) + "\":[";
        for (size_t i = 0; i < enderecos.size(); ++i)
        {
            const Endereco &e = enderecos[i];
            if (i > 0) out += ',';
            out += "{\"ip\":\"" + json_escape(e.ip) +
                   "\",\"versao\":\"" + json_escape(e.versao) +
                   "\",\"tipo\":\"" + json_escape(e.tipo) +
                   "\",\"mascara\":\"" + json_escape(e.mascara) + "\"}";
        }
        out += ']';
    }
    out += "}";
    if (incluir_modo)
    {
        out += ",\"modo\":\"" + json_escape(modo) + "\"";
    }
    out += "}";
    return out;
}

#if defined(_WIN32)

ResultadoEnvio enviar(const Config &cfg, const std::string &payload)
{
    ResultadoEnvio r;

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    std::wstring wurl = wide_utf8(cfg.url);
    std::wstring host, caminho;
    uc.lpszHostName = nullptr;
    uc.dwHostNameLength = 1;
    uc.lpszUrlPath = nullptr;
    uc.dwUrlPathLength = 1;
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc))
    {
        r.erro = "URL invalida";
        return r;
    }
    host.assign(uc.lpszHostName, uc.dwHostNameLength);
    caminho.assign(uc.lpszUrlPath ? uc.lpszUrlPath : L"/", uc.dwUrlPathLength);
    if (caminho.empty()) caminho = L"/";
    const bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    const INTERNET_PORT porta = uc.nPort;

    HINTERNET sessao = WinHttpOpen(wide_utf8("invpush/" INVPUSH_VERSION).c_str(),
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (sessao == nullptr)
    {
        r.erro = "falha WinHttpOpen";
        return r;
    }

    HINTERNET conexao = WinHttpConnect(sessao, host.c_str(), porta, 0);
    HINTERNET requisicao = nullptr;
    do
    {
        if (conexao == nullptr)
        {
            r.erro = "falha WinHttpConnect";
            break;
        }
        requisicao = WinHttpOpenRequest(
            conexao, L"POST", caminho.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            https ? WINHTTP_FLAG_SECURE : 0);
        if (requisicao == nullptr)
        {
            r.erro = "falha WinHttpOpenRequest";
            break;
        }

        const int timeout_ms = cfg.timeout_s * 1000;
        WinHttpSetTimeouts(requisicao, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

        if (!cfg.verificar_tls)
        {
            DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(requisicao, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
        }

        const std::wstring cabecalhos =
            L"Content-Type: application/json\r\n"
            L"Authorization: Bearer " + wide_utf8(cfg.token) + L"\r\n";
        const DWORD total = static_cast<DWORD>(payload.size());
        if (!WinHttpSendRequest(requisicao, cabecalhos.c_str(),
                                static_cast<DWORD>(cabecalhos.size()),
                                const_cast<char *>(payload.data()), total, total, 0))
        {
            r.erro = "falha WinHttpSendRequest (" + std::to_string(GetLastError()) + ")";
            break;
        }
        if (!WinHttpReceiveResponse(requisicao, nullptr))
        {
            r.erro = "falha WinHttpReceiveResponse (" + std::to_string(GetLastError()) + ")";
            break;
        }

        DWORD codigo = 0, tam = sizeof(codigo);
        WinHttpQueryHeaders(requisicao,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &codigo, &tam,
                            WINHTTP_NO_HEADER_INDEX);
        r.status_http = static_cast<long>(codigo);

        std::string corpo;
        for (;;)
        {
            DWORD disponivel = 0;
            if (!WinHttpQueryDataAvailable(requisicao, &disponivel) || disponivel == 0) break;
            std::vector<char> chunk(disponivel);
            DWORD lido = 0;
            if (!WinHttpReadData(requisicao, chunk.data(), disponivel, &lido) || lido == 0) break;
            corpo.append(chunk.data(), lido);
        }
        r.corpo = std::move(corpo);
        r.ok = r.status_http >= 200 && r.status_http < 300;
        if (!r.ok) r.erro = "HTTP " + std::to_string(r.status_http);
    } while (false);

    if (requisicao != nullptr) WinHttpCloseHandle(requisicao);
    if (conexao != nullptr) WinHttpCloseHandle(conexao);
    WinHttpCloseHandle(sessao);
    return r;
}

std::string obter_ip_publico()
{
    (void)wsa();
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    const std::wstring wurl = wide_utf8(kIpifyUrl);
    std::wstring host, caminho;
    uc.dwHostNameLength = 1;
    uc.dwUrlPathLength = 1;
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc))
    {
        return "Indisponível";
    }
    host.assign(uc.lpszHostName, uc.dwHostNameLength);
    caminho.assign(uc.lpszUrlPath ? uc.lpszUrlPath : L"/", uc.dwUrlPathLength);

    HINTERNET sessao = WinHttpOpen(L"invpush/" L"", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (sessao == nullptr) return "Indisponível";
    std::string saida = "Indisponível";

    HINTERNET conexao = WinHttpConnect(sessao, host.c_str(), uc.nPort, 0);
    HINTERNET req = nullptr;
    do
    {
        if (conexao == nullptr) break;
        req = WinHttpOpenRequest(conexao, L"GET", caminho.c_str(), nullptr,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
        if (req == nullptr) break;
        WinHttpSetTimeouts(req, kIpifyTimeoutS * 1000, kIpifyTimeoutS * 1000,
                           kIpifyTimeoutS * 1000, kIpifyTimeoutS * 1000);
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        {
            break;
        }
        if (!WinHttpReceiveResponse(req, nullptr)) break;

        DWORD codigo = 0, tam = sizeof(codigo);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &codigo, &tam,
                            WINHTTP_NO_HEADER_INDEX);
        if (codigo != 200) break;

        std::string corpo;
        for (;;)
        {
            DWORD disponivel = 0;
            if (!WinHttpQueryDataAvailable(req, &disponivel) || disponivel == 0) break;
            std::vector<char> chunk(disponivel);
            DWORD lido = 0;
            if (!WinHttpReadData(req, chunk.data(), disponivel, &lido) || lido == 0) break;
            corpo.append(chunk.data(), lido);
        }
        if (!corpo.empty()) saida = corpo;
    } while (false);

    if (req != nullptr) WinHttpCloseHandle(req);
    if (conexao != nullptr) WinHttpCloseHandle(conexao);
    WinHttpCloseHandle(sessao);
    return saida;
}

#else

namespace
{

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *out = static_cast<std::string *>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

CURLcode http_request(const Config *cfg_post, const char *url_get, const std::string *payload,
                      const std::string *token, int timeout_s, bool verificar_tls,
                      long *status, std::string *corpo, const char **erro)
{
    CURL *h = curl_easy_init();
    if (h == nullptr)
    {
        *erro = "falha ao criar handle curl";
        return CURLE_FAILED_INIT;
    }
    curl_slist *cabecalhos = nullptr;
    cabecalhos = curl_slist_append(cabecalhos, "Content-Type: application/json");
    if (cfg_post != nullptr && token != nullptr)
    {
        const std::string auth = "Authorization: Bearer " + *token;
        cabecalhos = curl_slist_append(cabecalhos, auth.c_str());
    }

    curl_easy_setopt(h, CURLOPT_URL, url_get);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, corpo);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_s) * 1000L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "invpush/" INVPUSH_VERSION);
    if (!verificar_tls)
    {
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    if (payload != nullptr && cfg_post != nullptr)
    {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, payload->c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload->size()));
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, cabecalhos);
    }

    const CURLcode res = curl_easy_perform(h);
    if (res == CURLE_OK)
    {
        long codigo = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &codigo);
        *status = codigo;
    }
    else
    {
        *erro = curl_easy_strerror(res);
    }
    curl_slist_free_all(cabecalhos);
    curl_easy_cleanup(h);
    return res;
}

} // namespace

ResultadoEnvio enviar(const Config &cfg, const std::string &payload)
{
    ResultadoEnvio r;
    static bool global_ok = [] { return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; }();
    if (!global_ok)
    {
        r.erro = "falha ao inicializar libcurl";
        return r;
    }

    const char *erro = nullptr;
    const CURLcode res = http_request(&cfg, cfg.url.c_str(), &payload, &cfg.token,
                                      cfg.timeout_s, cfg.verificar_tls,
                                      &r.status_http, &r.corpo, &erro);
    if (res == CURLE_OK)
    {
        r.ok = r.status_http >= 200 && r.status_http < 300;
        if (r.ok)
        {
            // 2xx com corpo vazio/marcador ausente indica proxy errado, não
            // ingestão bem-sucedida (ex.: rota pública antiga devolvia 200 "").
            const std::string status_json = json_campo_string(r.corpo, "status");
            r.ok = !r.corpo.empty() &&
                   (status_json == "success" || status_json == "ok");
            if (!r.ok) r.erro = "HTTP 2xx sem marcador de sucesso: " + r.corpo;
        }
        else
        {
            r.erro = "HTTP " + std::to_string(r.status_http);
        }
    }
    else
    {
        r.erro = erro != nullptr ? erro : "erro curl";
    }
    return r;
}

std::string obter_ip_publico()
{
    static const bool global_ok = [] { return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; }();
    if (!global_ok) return "Indisponível";

    long status = 0;
    std::string corpo;
    const char *erro = nullptr;
    Config dummy;
    const CURLcode res = http_request(nullptr, kIpifyUrl, nullptr, nullptr,
                                      kIpifyTimeoutS, true, &status, &corpo, &erro);
    if (res == CURLE_OK && status == 200 && !corpo.empty())
    {
        return corpo;
    }
    return "Indisponível";
}

#endif

// ------------------------------------------------------------------- CLI/run

void print_help(const char *prog)
{
    std::cout
        << "invpush v" << INVPUSH_VERSION << " — envio de inventario de maquinas\n\n"
        << "Uso: " << prog << " [opcoes]\n\n"
        << "Opcoes:\n"
        << "  --url URL            Endpoint de ingestao (padrao: " << kUrlPadrao << ")\n"
        << "  --token TOKEN        Bearer token de coleta (env INVENTORY_COLLECTION_API_TOKEN)\n"
        << "  --maquina NOME       Sobrescreve o hostname reportado\n"
        << "  --timeout SEG        Timeout do envio em segundos (padrao: 10)\n"
        << "  --janela-boot SEG    Uptime abaixo deste valor marca modo \"boot\" (padrao: 300)\n"
        << "  --ip-publico IP      Nao consulta api.ipify.org; usa o valor informado\n"
        << "  --print              Mostra o payload JSON e sai sem enviar\n"
        << "  --nao-verificar-tls  Desabilita verificacao do certificado TLS\n"
        << "  -d, --debug          Dumpa payload e resposta crua\n"
        << "  -q, --quiet          Suprime mensagens de progresso\n"
        << "  -h, --help           Esta ajuda\n"
        << "  --version            Versao do agente\n";
}

bool parse_args(int argc, char *argv[], Config &cfg)
{
    auto proximo = [&](int &i) -> const char * {
        if (i + 1 >= argc)
        {
            return nullptr;
        }
        return argv[++i];
    };
    auto numero = [](const char *s, int &valor) -> bool {
        if (s == nullptr || *s == '\0') return false;
        char *fim = nullptr;
        const long v = std::strtol(s, &fim, 10);
        if (fim == s || *fim != '\0' || v < 0 || v > 86400 * 30) return false;
        valor = static_cast<int>(v);
        return true;
    };

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--url")
        {
            const char *v = proximo(i);
            if (v == nullptr) return false;
            cfg.url = v;
            cfg.cli_url = true;
        }
        else if (arg == "--token")
        {
            const char *v = proximo(i);
            if (v == nullptr) return false;
            cfg.token = v;
            cfg.cli_token = true;
        }
        else if (arg == "--maquina")
        {
            const char *v = proximo(i);
            if (v == nullptr) return false;
            cfg.maquina = v;
            cfg.cli_maquina = true;
        }
        else if (arg == "--timeout")
        {
            const char *v = proximo(i);
            if (v == nullptr || !numero(v, cfg.timeout_s)) return false;
            cfg.cli_timeout = true;
        }
        else if (arg == "--janela-boot")
        {
            const char *v = proximo(i);
            if (v == nullptr || !numero(v, cfg.janela_boot_s)) return false;
            cfg.cli_janela_boot = true;
        }
        else if (arg == "--ip-publico")
        {
            const char *v = proximo(i);
            if (v == nullptr) return false;
            cfg.ip_publico_fixo = v;
            cfg.cli_ip_publico = true;
        }
        else if (arg == "--print")
        {
            cfg.imprimir = true;
        }
        else if (arg == "--nao-verificar-tls")
        {
            cfg.verificar_tls = false;
            cfg.cli_verificar_tls = true;
        }
        else if (arg == "-q" || arg == "--quiet")
        {
            cfg.silencioso = true;
        }
        else if (arg == "-d" || arg == "--debug")
        {
            cfg.debug = true;
        }
        else if (arg == "-h" || arg == "--help" || arg == "--ajuda")
        {
            cfg.ajuda = true;
        }
        else if (arg == "--version" || arg == "--versao")
        {
            cfg.versao = true;
        }
        else
        {
            std::cerr << "argumento desconhecido: " << arg << "\n";
            return false;
        }
    }
    return true;
}

void apply_env(Config &cfg)
{
    if (cfg.url.empty())
    {
        if (const char *e = std::getenv("INVENTORY_API_URL"); e != nullptr && *e != '\0')
        {
            cfg.url = e;
        }
        else
        {
            cfg.url = kUrlPadrao;
        }
    }
    if (cfg.token.empty())
    {
        if (const char *e = std::getenv("INVENTORY_COLLECTION_API_TOKEN");
            e != nullptr && *e != '\0')
        {
            cfg.token = e;
        }
    }
}

int run(Config cfg)
{
    if (cfg.imprimir)
    {
        // Modo teste: payload completo com coleta real, sem rede nem token.
        const std::string hostname = !cfg.maquina.empty() ? cfg.maquina : hostname_do_sistema();
        const Ifaces interfaces = coletar_interfaces();
        const std::string modo = detectar_modo(uptime_segundos(), cfg.janela_boot_s);
        const std::string ip_publico =
            !cfg.ip_publico_fixo.empty() ? cfg.ip_publico_fixo : obter_ip_publico();
        std::cout << montar_payload(hostname, interfaces, modo, ip_publico) << "\n";
        return 0;
    }

    if (cfg.url.empty())
    {
        log_erro("ERRO FATAL: URL de destino ausente (use --url ou INVENTORY_API_URL).");
        return 2;
    }
    if (cfg.token.empty())
    {
        log_erro("ERRO FATAL: token de coleta ausente (use --token ou "
                 "INVENTORY_COLLECTION_API_TOKEN).");
        return 2;
    }

    if (!cfg.silencioso)
    {
        log_info("--- INICIANDO COLETA ---");
    }

    const std::string hostname = !cfg.maquina.empty() ? cfg.maquina : hostname_do_sistema();
    const Ifaces interfaces = coletar_interfaces();
    const long uptime = uptime_segundos();
    const std::string modo = detectar_modo(uptime, cfg.janela_boot_s);
    const std::string ip_publico =
        !cfg.ip_publico_fixo.empty() ? cfg.ip_publico_fixo : obter_ip_publico();

    if (!cfg.ip_publico_fixo.empty() && !cfg.silencioso)
    {
        log_debug(cfg, "IP publico fixado por flag: " + ip_publico);
    }

    const std::string payload = montar_payload(hostname, interfaces, modo, ip_publico);
    log_debug(cfg, "--- PAYLOAD JSON A SER ENVIADO ---\n" + payload + "\n---");

    if (!cfg.silencioso)
    {
        log_info("Enviando dados para " + cfg.url + "...");
    }

    const ResultadoEnvio res = enviar(cfg, payload);

    if (res.ok)
    {
        log_debug(cfg, "Status Code: " + std::to_string(res.status_http));
        log_debug(cfg, "Resposta RAW do Servidor:\n" + res.corpo);
        if (!cfg.silencioso)
        {
            log_info("SUCESSO: Dados aceitos pelo servidor.");
            const std::string mensagem = json_campo_string(res.corpo, "mensagem");
            if (!mensagem.empty()) log_info("Msg do Servidor: " + mensagem);
            const std::string id = json_campo_string(res.corpo, "id");
            if (!id.empty()) log_info("ID da maquina no banco: " + id);
        }
        return 0;
    }

    if (res.status_http > 0)
    {
        log_erro("ERRO DO SERVIDOR: Codigo " + std::to_string(res.status_http) +
                 (res.corpo.empty() ? "" : (" | " + res.corpo)));
    }
    else
    {
        log_erro(std::string("FALHA CRITICA DE CONEXAO: ") +
                 (res.erro.empty() ? "erro desconhecido" : res.erro));
    }
    return 3;
}

} // namespace invpush
