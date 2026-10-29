// Suíte de testes do invpush (framework mínimo, table-driven).
// Cobre as funções puras: JSON, máscaras, classificação de IPs,
// detecção de modo, montagem do payload e parsing de argumentos.
#include "test_framework.hpp"

#include "invpush.hpp"
#include "selfupdate.hpp"

#include <cstdlib>
#include <iostream>

using namespace invpush;

TEST("json_escape preserva texto simples e escapa especiais")
{
    CHECK(json_escape("abc 123") == "abc 123");
    CHECK(json_escape("a\"b") == "a\\\"b");
    CHECK(json_escape("a\\b") == "a\\\\b");
    CHECK(json_escape("a\nb\tc") == "a\\nb\\tc");
    std::string ctl = "x";
    ctl += static_cast<char>(1);
    CHECK(json_escape(ctl) == "x\\u0001");
    // UTF-8 multibyte passa intacto
    CHECK(json_escape("Máquina") == "Máquina");
}

TEST("mascara_ipv4 converte prefixos em dotted quad")
{
    CHECK(mascara_ipv4(24) == "255.255.255.0");
    CHECK(mascara_ipv4(8) == "255.0.0.0");
    CHECK(mascara_ipv4(32) == "255.255.255.255");
    CHECK(mascara_ipv4(0) == "0.0.0.0");
    CHECK(mascara_ipv4(30) == "255.255.255.252");
}

TEST("mascara_ipv6 usa forma expandida estilo psutil")
{
    CHECK(mascara_ipv6(64) == "ffff:ffff:ffff:ffff::");
    CHECK(mascara_ipv6(128) == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    CHECK(mascara_ipv6(16) == "ffff::");
    CHECK(mascara_ipv6(0) == "::");
    CHECK(mascara_ipv6(48) == "ffff:ffff:ffff::");
    // Clamp de valores absurdos
    CHECK(mascara_ipv6(200) == mascara_ipv6(128));
    CHECK(mascara_ipv6(-5) == "::");
}

TEST("prefixo_de_mascara valida contiguidade")
{
    int p = -1;
    CHECK(prefixo_de_mascara("255.255.255.0", p));
    CHECK(p == 24);
    CHECK(prefixo_de_mascara("0.0.0.0", p));
    CHECK(p == 0);
    CHECK(prefixo_de_mascara("255.0.255.0", p) == false); // não contígua
    CHECK(prefixo_de_mascara("abc", p) == false);
    CHECK(prefixo_de_mascara("256.1.1.1", p) == false);
}

TEST("parse_ipv4 rejeita octetos fora da faixa")
{
    unsigned char o[4] = {0, 0, 0, 0};
    CHECK(parse_ipv4("192.168.0.50", o));
    CHECK(o[0] == 192 && o[3] == 50);
    CHECK(parse_ipv4("256.1.1.1", o) == false);
    CHECK(parse_ipv4("1.2.3", o) == false);
    CHECK(parse_ipv4("a.b.c.d", o) == false);
}

TEST("expandir_ipv6 cobre formas completa, comprimida e com zona")
{
    unsigned short g[8];
    CHECK(expandir_ipv6("::1", g));
    CHECK(g[7] == 1 && g[0] == 0);
    CHECK(expandir_ipv6("2001:db8::1", g));
    CHECK(g[0] == 0x2001 && g[1] == 0x0DB8 && g[7] == 1 && g[2] == 0);
    CHECK(expandir_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001", g));
    CHECK(g[7] == 1);
    CHECK(expandir_ipv6("fe80::1%eth0", g)); // zona descartada
    CHECK(g[0] == 0xFE80);
    CHECK(expandir_ipv6("1::2::3", g) == false);
    CHECK(expandir_ipv6("", g) == false);
    CHECK(expandir_ipv6("12345::", g) == false); // grupo > 4 dígitos
}

// A ordem elif do legado tem prioridade: loopback -> private -> link-local ->
// global -> outro. Em IPv4, 169.254/16 é private no ipaddress, então cai em
// "Privado (LAN)" antes de chegar ao ramo de link-local.
TEST("classificar_ipv4 replica a ordem do coletor legado")
{
    CHECK(classificar_ipv4("127.0.0.1") == "Loopback (Interno)");
    CHECK(classificar_ipv4("10.1.2.3") == "Privado (LAN)");
    CHECK(classificar_ipv4("172.16.0.1") == "Privado (LAN)");
    CHECK(classificar_ipv4("172.31.255.255") == "Privado (LAN)");
    CHECK(classificar_ipv4("172.32.0.1") == "Público (Internet)");
    CHECK(classificar_ipv4("192.168.1.10") == "Privado (LAN)");
    CHECK(classificar_ipv4("169.254.9.9") == "Privado (LAN)");
    CHECK(classificar_ipv4("8.8.8.8") == "Público (Internet)");
    CHECK(classificar_ipv4("100.64.0.1") == "Reservado/Outro"); // CGNAT
    CHECK(classificar_ipv4("203.0.113.9") == "Privado (LAN)");  // TEST-NET-3 é private
    CHECK(classificar_ipv4("999.1.1.1") == "Inválido");
}

TEST("classificar_ipv6 replica faixas privadas do ipaddress")
{
    CHECK(classificar_ipv6("::1") == "Loopback (Interno)");
    CHECK(classificar_ipv6("fe80::1234:5678") == "Privado (LAN)");
    CHECK(classificar_ipv6("fd12:3456::1") == "Privado (LAN)");
    CHECK(classificar_ipv6("2001:db8::1") == "Privado (LAN)");
    CHECK(classificar_ipv6("2606:4700::1111") == "Público (Internet)");
    CHECK(classificar_ipv6("2a01:5c0::9") == "Público (Internet)");
    CHECK(classificar_ipv6("nope") == "Inválido");
}

TEST("detectar_modo marca boot dentro da janela")
{
    CHECK(detectar_modo(0, 300) == "boot");
    CHECK(detectar_modo(299, 300) == "boot");
    CHECK(detectar_modo(300, 300) == "normal");
    CHECK(detectar_modo(100000, 300) == "normal");
    CHECK(detectar_modo(-1, 300) == "normal"); // uptime indisponível
}

TEST("montar_payload produz contrato host_inventory")
{
    Ifaces ifaces;
    ifaces["eth0"] = {
        {"192.168.0.50", "IPv4", "Privado (LAN)", "255.255.255.0"},
        {"fe80::1", "IPv6", "Privado (LAN)", "ffff:ffff:ffff:ffff::"},
    };

    const std::string payload =
        montar_payload("NB-01", ifaces, "boot", "203.0.113.42");
    const std::string esperado =
        "{\"maquina\":\"NB-01\",\"ip_publico_saida\":\"203.0.113.42\","
        "\"interfaces\":{\"eth0\":["
        "{\"ip\":\"192.168.0.50\",\"versao\":\"IPv4\",\"tipo\":\"Privado (LAN)\","
        "\"mascara\":\"255.255.255.0\"},"
        "{\"ip\":\"fe80::1\",\"versao\":\"IPv6\",\"tipo\":\"Privado (LAN)\","
        "\"mascara\":\"ffff:ffff:ffff:ffff::\"}]},"
        "\"modo\":\"boot\"}";
    CHECK(payload == esperado);

    // Sem modo (contrato legado puro) e sem interfaces
    const std::string legado =
        montar_payload("PC-02", {}, "normal", "Indisponível", false);
    CHECK(legado ==
          "{\"maquina\":\"PC-02\",\"ip_publico_saida\":\"Indisponível\","
          "\"interfaces\":{}}");

    // Hostname com caractere especial é escapado
    const std::string escapado = montar_payload("MA\"QUINA", {}, "normal", "");
    CHECK(escapado.find("\"maquina\":\"MA\\\"QUINA\"") != std::string::npos);
}

// --- configuração persistente ------------------------------------------------

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>

namespace fs = std::filesystem;

struct TempDirCfg
{
    fs::path dir;
    TempDirCfg()
    {
        const auto tick =
            std::chrono::steady_clock::now().time_since_epoch().count();
        dir = fs::temp_directory_path() / ("invpush_test_tmp_" + std::to_string(tick));
        fs::create_directories(dir);
    }
    ~TempDirCfg() { std::error_code ec; fs::remove_all(dir, ec); }
};

static void escrever_cfg(const fs::path &p, const std::string &conteudo)
{
    std::ofstream f(p);
    f << conteudo;
}

static int rodar_config(std::vector<std::string> args)
{
    std::vector<char *> argv;
    argv.push_back(const_cast<char *>("invpush"));
    for (auto &s : args)
        argv.push_back(const_cast<char *>(s.c_str()));
    return comando_config(static_cast<int>(argv.size()), argv.data());
}

TEST("NivelConfig: define/busca/acrescenta/remove")
{
    NivelConfig n;
    CHECK(n.vazia());
    CHECK(n.busca("url") == nullptr);

    n.define("url", {"https://api.exemplo"});
    CHECK(!n.vazia());
    const auto *u = n.busca("url");
    CHECK(u != nullptr);
    if (u == nullptr)
        return;
    CHECK(u->size() == 1 && (*u)[0] == "https://api.exemplo");

    n.acrescenta("token", {"abc"});
    n.define("url", {"https://outro"});
    u = n.busca("url");
    if (u != nullptr)
        CHECK(u->size() == 1 && (*u)[0] == "https://outro");

    n.remove("url");
    n.remove("inexistente"); // sem efeito
    CHECK(n.busca("url") == nullptr);
}

TEST("chave_valida aceita exatamente as 7 chaves")
{
    CHECK(chave_valida("url"));
    CHECK(chave_valida("token"));
    CHECK(chave_valida("maquina"));
    CHECK(chave_valida("ip-publico"));
    CHECK(chave_valida("timeout"));
    CHECK(chave_valida("janela-boot"));
    CHECK(chave_valida("verificar-tls"));
    CHECK(!chave_valida("outra"));
    CHECK(!chave_valida(""));
}

TEST("valor_bool interpreta variantes e cai no padrao")
{
    CHECK(valor_bool("true", false));
    CHECK(valor_bool("TRUE", false));
    CHECK(valor_bool(" 1 ", true));
    CHECK(valor_bool("sim", false));
    CHECK(!valor_bool("false", true));
    CHECK(!valor_bool("off", true));
    CHECK(!valor_bool("nao", true));
    CHECK(valor_bool("lixo", true));   // padrão
    CHECK(!valor_bool("lixo", false)); // padrão
}

TEST("caminho_config_global respeita INVPUSH_CONFIG_HOME")
{
#ifdef _WIN32
    _putenv_s("INVPUSH_CONFIG_HOME", "C:\\sandbox");
#else
    setenv("INVPUSH_CONFIG_HOME", "/sandbox", 1);
#endif
    const fs::path p = caminho_config_global();
#ifdef _WIN32
    CHECK(p == fs::path("C:\\sandbox") / "invpush" / "config.txt");
#else
    CHECK(p == fs::path("/sandbox") / "invpush" / "config");
#endif
#ifdef _WIN32
    _putenv_s("INVPUSH_CONFIG_HOME", "");
#else
    unsetenv("INVPUSH_CONFIG_HOME");
#endif
}

TEST("descobrir_config_local sobe a hierarquia ate encontrar .invpush.conf")
{
    TempDirCfg raiz;
    fs::create_directories(raiz.dir / "a" / "b");
    escrever_cfg(raiz.dir / ".invpush.conf", "timeout=20\n");

    CHECK(!descobrir_config_local(raiz.dir / "a" / "b").empty());
    CHECK(descobrir_config_local(raiz.dir / "a" / "b").filename() == ".invpush.conf");
    CHECK(descobrir_config_local(raiz.dir).filename() == ".invpush.conf");

    TempDirCfg sem_config;
    CHECK(descobrir_config_local(sem_config.dir).empty());
}

TEST("carregar_nivel: formato chave=valor, comentarios e lixo ignorado")
{
    TempDirCfg td;
    escrever_cfg(td.dir / "cfg",
                 "# comentario\n"
                 "\n"
                 "timeout=45\n"
                 " maquina = SERVIDOR-X \n"
                 "sem-igual\n"
                 "desconhecida=x\n"
                 "verificar-tls=false\n");

    std::ostringstream vazio;
    auto *antigo = std::cerr.rdbuf(vazio.rdbuf());
    const NivelConfig n = carregar_nivel(td.dir / "cfg");
    std::cerr.rdbuf(antigo);

    const auto *t = n.busca("timeout");
    CHECK(t != nullptr);
    if (t == nullptr)
        return;
    CHECK((*t)[0] == "45");

    const auto *m = n.busca("maquina");
    CHECK(m != nullptr);
    if (m == nullptr)
        return;
    CHECK((*m)[0] == "SERVIDOR-X");

    CHECK(n.busca("desconhecida") == nullptr);
    const auto *v = n.busca("verificar-tls");
    CHECK(v != nullptr);
    if (v != nullptr)
        CHECK(valor_bool((*v)[0], true) == false);
}

#ifndef _WIN32
TEST("salvar_nivel grava a config (com token) so para o dono")
{
    TempDirCfg td;
    NivelConfig n;
    n.define("token", {"TOKEN_FICTICIO"});
    CHECK(salvar_nivel(td.dir / "cfg", n));
    const auto p = std::filesystem::status(td.dir / "cfg").permissions();
    using P = std::filesystem::perms;
    CHECK((p & (P::group_all | P::others_all)) == P::none);
    CHECK((p & P::owner_read) != P::none);
}
#endif

TEST("salvar/carregar roundtrip deterministico com valor contendo '='")
{
    TempDirCfg td;
    NivelConfig n;
    n.define("url", {"https://api/?a=b"});
    n.define("token", {"tok=en"});
    CHECK(salvar_nivel(td.dir / "cfg", n));

    std::ifstream in(td.dir / "cfg");
    const std::string bruto((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    CHECK(bruto.find("token=tok=en") != std::string::npos); // split no primeiro '='
    CHECK(bruto.find("# invpush") != std::string::npos);
    CHECK(bruto.find("texto puro") != std::string::npos);   // aviso do token

    const NivelConfig lido = carregar_nivel(td.dir / "cfg");
    const auto *tok = lido.busca("token");
    CHECK(tok != nullptr);
    if (tok == nullptr)
        return;
    CHECK((*tok)[0] == "tok=en"); // split no primeiro '=' preserva o resto
    // ordem alfabética: token antes de url
    CHECK(bruto.find("token=") < bruto.find("url="));
}

TEST("mesclar_niveis: local sobrepoe global por chave inteira")
{
    NivelConfig g, l;
    g.define("url", {"https://global"});
    g.define("timeout", {"10"});
    l.define("url", {"https://local"});

    const NivelConfig m = mesclar_niveis(g, l);
    const auto *u = m.busca("url");
    CHECK(u != nullptr);
    if (u == nullptr)
        return;
    CHECK(u->size() == 1 && (*u)[0] == "https://local");
    const auto *t = m.busca("timeout");
    CHECK(t != nullptr);
    if (t == nullptr)
        return;
    CHECK((*t)[0] == "10");
}

TEST("aplicar_config: preenche apenas opcoes ausentes na CLI")
{
    Config cfg = {};
    cfg.timeout_s = 10;
    cfg.janela_boot_s = 300;
    cfg.verificar_tls = true;

    char *argv[] = {const_cast<char *>("invpush"),
                    const_cast<char *>("--url"), const_cast<char *>("https://cli"),
                    const_cast<char *>("--nao-verificar-tls")};
    CHECK(parse_args(4, argv, cfg));

    NivelConfig efetivo;
    efetivo.define("url", {"https://da-config"});      // ignorado: CLI vence
    efetivo.define("token", {"tok-config"});           // aplicado
    efetivo.define("maquina", {"HOST-CFG"});           // aplicado
    efetivo.define("timeout", {"60"});                 // aplicado
    efetivo.define("janela-boot", {"120"});            // aplicado
    efetivo.define("verificar-tls", {"true"});         // ignorado: CLI vence
    aplicar_config(cfg, efetivo);

    CHECK(cfg.url == "https://cli" && cfg.cli_url);
    CHECK(cfg.token == "tok-config");
    CHECK(cfg.maquina == "HOST-CFG");
    CHECK(cfg.timeout_s == 60);
    CHECK(cfg.janela_boot_s == 120);
    CHECK(cfg.verificar_tls == false); // flag da CLI permanece
}

TEST("aplicar_config: timeout/janela invalidos na config sao ignorados com aviso")
{
    Config cfg = {};
    cfg.timeout_s = 10;
    cfg.janela_boot_s = 300;
    cfg.verificar_tls = true;

    NivelConfig efetivo;
    efetivo.define("timeout", {"abc"});
    efetivo.define("janela-boot", {"-7"});

    std::ostringstream vazio;
    auto *antigo = std::cerr.rdbuf(vazio.rdbuf());
    aplicar_config(cfg, efetivo);
    std::cerr.rdbuf(antigo);

    CHECK(cfg.timeout_s == 10);     // mantém o padrão
    CHECK(cfg.janela_boot_s == 300);
}

TEST("comando_config: ciclo set -> get -> list -> unset em escopo global sandbox")
{
#ifdef _WIN32
    TempDirCfg td;
    std::string home = td.dir.string();
    _putenv_s("INVPUSH_CONFIG_HOME", home.c_str());
#else
    TempDirCfg td;
    setenv("INVPUSH_CONFIG_HOME", td.dir.string().c_str(), 1);
#endif

    CHECK(rodar_config({"config", "set", "url", "https://api.local"}) == EXIT_SUCCESS);
    CHECK(fs::exists(caminho_config_global()));

    CHECK(rodar_config({"config", "get", "url"}) == EXIT_SUCCESS);
    CHECK(rodar_config({"config", "list"}) == EXIT_SUCCESS);
    CHECK(rodar_config({"config", "path"}) == EXIT_SUCCESS);
    CHECK(rodar_config({"config", "get", "inexistente"}) == EXIT_FAILURE);
    CHECK(rodar_config({"config", "set", "chave_mala", "x"}) == EXIT_FAILURE);
    CHECK(rodar_config({"config", "verbo_falso"}) == EXIT_FAILURE);

    CHECK(rodar_config({"config", "unset", "url"}) == EXIT_SUCCESS);
    CHECK(rodar_config({"config", "get", "url"}) == EXIT_FAILURE);

#ifdef _WIN32
    _putenv_s("INVPUSH_CONFIG_HOME", "");
#else
    unsetenv("INVPUSH_CONFIG_HOME");
#endif
}

TEST("comando_config: --local grava ./.invpush.conf no diretorio atual")
{
#ifdef _WIN32
    TempDirCfg td;
    std::string home = td.dir.string();
    _putenv_s("INVPUSH_CONFIG_HOME", home.c_str());
#else
    TempDirCfg td;
    setenv("INVPUSH_CONFIG_HOME", td.dir.string().c_str(), 1);
#endif

    const fs::path original = fs::current_path();
    std::error_code ec;
    fs::current_path(td.dir, ec);
    if (ec)
        return;

    CHECK(rodar_config({"config", "--local", "set", "maquina", "HOST-LOCAL"}) == EXIT_SUCCESS);
    CHECK(fs::exists(td.dir / ".invpush.conf"));

    const NivelConfig lido = carregar_nivel(td.dir / ".invpush.conf");
    const auto *v = lido.busca("maquina");
    CHECK(v != nullptr);
    if (v == nullptr)
        return;
    CHECK((*v)[0] == "HOST-LOCAL");
    CHECK(descobrir_config_local(td.dir) == td.dir / ".invpush.conf");

    fs::current_path(original, ec);

#ifdef _WIN32
    _putenv_s("INVPUSH_CONFIG_HOME", "");
#else
    unsetenv("INVPUSH_CONFIG_HOME");
#endif
}

// ---------------------------------------------------------------------------
// selfupdate (compartilhado entre os compilados)
// ---------------------------------------------------------------------------

TEST("selfupdate: sha256 de vetores conhecidos (FIPS 180-4)")
{
    CHECK(selfupdate::sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(selfupdate::sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(selfupdate::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(selfupdate::sha256_hex(std::string(1000000, 'a')) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST("selfupdate: semver aceita prefixo v e ignora sufixo rc")
{
    const auto v = selfupdate::parse_semver("v1.12.3-rc.1");
    CHECK(v.ok && v.major == 1 && v.minor == 12 && v.patch == 3);
    CHECK(!selfupdate::parse_semver("1.2").ok);
    CHECK(!selfupdate::parse_semver("1.2.x").ok);
    CHECK(!selfupdate::parse_semver("").ok);
    CHECK(selfupdate::cmp_semver(selfupdate::parse_semver("1.2.10"),
                                 selfupdate::parse_semver("1.10.0")) < 0);
    CHECK(selfupdate::cmp_semver(selfupdate::parse_semver("2.0.0"),
                                 selfupdate::parse_semver("v2.0.0")) == 0);
}

TEST("selfupdate: assets pelo basename de browser_download_url")
{
    const std::string json =
        R"({"tag_name":"v1.3.0","assets":[{"name":"x","uploader":{"login":"a"},)"
        R"("browser_download_url":"https://github.com/o/r/releases/download/v1.3.0/invpush-linux-aarch64"},)"
        R"({"browser_download_url":"https://github.com/o/r/releases/download/v1.3.0/SHA256SUMS"}]})";
    const auto a = selfupdate::json_assets(json);
    CHECK(a.size() == 2);
    if (a.size() == 2)
    {
        CHECK(a[0].first == "invpush-linux-aarch64");
        CHECK(a[1].first == "SHA256SUMS");
    }
    CHECK(selfupdate::json_string_field(json, "tag_name") == "v1.3.0");
}

TEST("selfupdate: hash_em_sumas acha o arquivo exato")
{
    const std::string h(64, 'a');
    const std::string sumas = std::string(64, 'b') + "  invpush-linux-x86_64\n" + h +
                              " *invpush-linux-aarch64\n" + "zz  invpush-windows-x86.exe\n";
    CHECK(selfupdate::hash_em_sumas(sumas, "invpush-linux-aarch64") == h);
    CHECK(selfupdate::hash_em_sumas(sumas, "invpush-linux-arm32").empty());
    CHECK(selfupdate::hash_em_sumas(sumas, "invpush-windows-x86.exe").empty());
}

TEST("selfupdate: nome do artefato segue o padrao do release.yml")
{
    const std::string n = selfupdate::nome_artefato("invpush");
    CHECK(n.rfind("invpush-linux-", 0) == 0 || n.rfind("invpush-windows-", 0) == 0);
}

int main()
{
    return tests::run_all();
}
