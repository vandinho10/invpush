// Suíte de testes do invpush (framework mínimo, table-driven).
// Cobre as funções puras: JSON, máscaras, classificação de IPs,
// detecção de modo, montagem do payload e parsing de argumentos.
#include "test_framework.hpp"

#include "invpush.hpp"

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

int main()
{
    return tests::run_all();
}
