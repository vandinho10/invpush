#include "invpush.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>

#ifdef _WIN32
#include <windows.h>
#endif

namespace invpush
{

namespace
{

const std::set<std::string> CHAVES_VALIDAS = {
    "url", "token", "maquina", "ip-publico", "timeout", "janela-boot",
    "verificar-tls"};

const char *NOME_ARQUIVO_LOCAL = ".invpush.conf";

std::string aparar(const std::string &s)
{
    size_t ini = 0, fim = s.size();
    while (ini < fim && (s[ini] == ' ' || s[ini] == '\t' || s[ini] == '\r'))
        ++ini;
    while (fim > ini && (s[fim - 1] == ' ' || s[fim - 1] == '\t' || s[fim - 1] == '\r'))
        --fim;
    return s.substr(ini, fim - ini);
}

std::string minusculas(std::string s)
{
    for (char &c : s)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// Mesmos limites do numero() do parse_args.
bool numero_config(const std::string &texto, int &valor)
{
    if (texto.empty())
        return false;
    char *fim = nullptr;
    const long v = std::strtol(texto.c_str(), &fim, 10);
    if (fim == texto.c_str() || *fim != '\0' || v < 0 || v > 86400 * 30)
        return false;
    valor = static_cast<int>(v);
    return true;
}

std::vector<std::string> *busca_linear(
    std::vector<std::pair<std::string, std::vector<std::string>>> &entradas,
    const std::string &chave)
{
    for (auto &par : entradas)
        if (par.first == chave)
            return &par.second;
    return nullptr;
}

} // namespace

// ------------------------------- NivelConfig -------------------------------

bool NivelConfig::vazia() const { return entradas.empty(); }

const std::vector<std::string> *NivelConfig::busca(const std::string &chave) const
{
    for (const auto &par : entradas)
        if (par.first == chave)
            return &par.second;
    return nullptr;
}

void NivelConfig::define(const std::string &chave, std::vector<std::string> valores)
{
    if (auto *existente = busca_linear(entradas, chave))
    {
        *existente = std::move(valores);
        return;
    }
    entradas.emplace_back(chave, std::move(valores));
}

void NivelConfig::acrescenta(const std::string &chave,
                             const std::vector<std::string> &valores)
{
    if (auto *existente = busca_linear(entradas, chave))
    {
        for (const auto &v : valores)
            if (std::find(existente->begin(), existente->end(), v) == existente->end())
                existente->push_back(v);
        return;
    }
    entradas.emplace_back(chave, valores);
}

void NivelConfig::remove(const std::string &chave)
{
    entradas.erase(
        std::remove_if(entradas.begin(), entradas.end(),
                       [&chave](const auto &par) { return par.first == chave; }),
        entradas.end());
}

// ------------------------------ chaves / bool ------------------------------

bool chave_valida(const std::string &chave) { return CHAVES_VALIDAS.count(chave) > 0; }

bool valor_bool(const std::string &valor, bool padrao)
{
    const std::string v = minusculas(aparar(valor));
    if (v == "true" || v == "1" || v == "sim" || v == "yes" || v == "on")
        return true;
    if (v == "false" || v == "0" || v == "nao" || v == "não" || v == "no" || v == "off")
        return false;
    return padrao;
}

// --------------------------------- caminhos ---------------------------------

std::filesystem::path caminho_config_global()
{
#ifdef _WIN32
    const char *base = std::getenv("INVPUSH_CONFIG_HOME");
    if (base != nullptr && *base != '\0')
        return std::filesystem::path(base) / "invpush" / "config.txt";
    base = std::getenv("APPDATA");
    if (base != nullptr && *base != '\0')
        return std::filesystem::path(base) / "invpush" / "config.txt";
    base = std::getenv("USERPROFILE");
    if (base != nullptr && *base != '\0')
        return std::filesystem::path(base) / "invpush" / "config.txt";
    return {};
#else
    const char *base = std::getenv("INVPUSH_CONFIG_HOME");
    if (base != nullptr && *base != '\0')
        return std::filesystem::path(base) / "invpush" / "config";
    base = std::getenv("XDG_CONFIG_HOME");
    if (base == nullptr || *base == '\0')
    {
        base = std::getenv("HOME");
        if (base == nullptr || *base == '\0')
            return {};
        return std::filesystem::path(base) / ".config" / "invpush" / "config";
    }
    return std::filesystem::path(base) / "invpush" / "config";
#endif
}

std::filesystem::path descobrir_config_local(const std::filesystem::path &inicio)
{
    std::error_code ec;
    std::filesystem::path dir = std::filesystem::absolute(inicio, ec);
    if (ec)
        return {};

    while (true)
    {
        const std::filesystem::path candidato = dir / NOME_ARQUIVO_LOCAL;
        if (std::filesystem::exists(candidato, ec) && !ec)
            return candidato;
        const std::filesystem::path pai = dir.parent_path();
        if (pai == dir || pai.empty())
            break;
        dir = pai;
    }
    return {};
}

// ------------------------------ carregar/salvar ------------------------------

NivelConfig carregar_nivel(const std::filesystem::path &arquivo)
{
    NivelConfig nivel;
    if (arquivo.empty())
        return nivel;

    std::ifstream in(arquivo);
    if (!in.is_open())
        return nivel; // ausente ou ilegível: nível vazio, sem erro fatal

    std::string linha;
    while (std::getline(in, linha))
    {
        const std::string conteudo = aparar(linha);
        if (conteudo.empty() || conteudo[0] == '#')
            continue;

        const size_t pos = conteudo.find('=');
        if (pos == std::string::npos)
        {
            std::cerr << "invpush: aviso: linha invalida em " << arquivo.string()
                      << " (esperado chave=valor): " << conteudo << "\n";
            continue;
        }

        const std::string chave = aparar(conteudo.substr(0, pos));
        const std::string valor = aparar(conteudo.substr(pos + 1));
        if (!chave_valida(chave))
        {
            std::cerr << "invpush: aviso: chave desconhecida ignorada -> " << chave << "\n";
            continue;
        }
        nivel.acrescenta(chave, {valor});
    }
    return nivel;
}

bool salvar_nivel(const std::filesystem::path &arquivo, const NivelConfig &nivel)
{
    if (arquivo.empty())
        return false;

    std::error_code ec;
    std::filesystem::create_directories(arquivo.parent_path(), ec); // erro tolerável se já existe

    // Cópia ordenada por chave para saída determinística.
    NivelConfig ordenado = nivel;
    std::sort(ordenado.entradas.begin(), ordenado.entradas.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    const std::filesystem::path temporario = arquivo.string() + ".tmp";
    {
        std::ofstream out(temporario, std::ios::trunc);
        if (!out.is_open())
            return false;
        // O token fica em texto puro: restringe ao dono antes de gravar qualquer
        // conteúdo (o umask padrão deixaria 0644, legível por outros usuários).
        std::filesystem::permissions(temporario,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, ec);
        if (ec)
            return false;
        out << "# invpush — configuracao persistente\n";
        out << "# edite a mao ou use: invpush config set|add|unset [--global|--local]\n";
        out << "# atencao: token e armazenado em texto puro (como git credentials)\n";
        for (const auto &[chave, valores] : ordenado.entradas)
            for (const auto &valor : valores)
                out << chave << "=" << valor << "\n";
    }

    std::filesystem::rename(temporario, arquivo, ec);
    if (ec)
    {
        std::error_code ec_rm;
        std::filesystem::remove(temporario, ec_rm);
        return false;
    }

#ifdef _WIN32
    // Espelha o comportamento de dotfiles do Linux: oculta o arquivo local.
    if (arquivo.filename() == NOME_ARQUIVO_LOCAL)
        SetFileAttributesW(arquivo.c_str(), FILE_ATTRIBUTE_HIDDEN);
#endif
    return true;
}

// --------------------------------- mesclagem ---------------------------------

NivelConfig mesclar_niveis(const NivelConfig &global, const NivelConfig &local)
{
    NivelConfig efetivo = global;
    for (const auto &[chave, valores] : local.entradas)
        efetivo.define(chave, valores);
    return efetivo;
}

// ------------------------------- aplicar config ------------------------------

void aplicar_config(Config &cfg, const NivelConfig &efetivo)
{
    if (efetivo.vazia())
        return;

    auto primeiro = [&efetivo](const char *chave) -> const std::string *
    {
        const auto *v = efetivo.busca(chave);
        if (v == nullptr || v->empty())
            return nullptr;
        return &v->front();
    };

    if (!cfg.cli_url)
    {
        if (const std::string *s = primeiro("url"))
            cfg.url = *s;
    }

    if (!cfg.cli_token)
    {
        if (const std::string *s = primeiro("token"))
            cfg.token = *s;
    }

    if (!cfg.cli_maquina)
    {
        if (const std::string *s = primeiro("maquina"))
            cfg.maquina = *s;
    }

    if (!cfg.cli_ip_publico)
    {
        if (const std::string *s = primeiro("ip-publico"))
            cfg.ip_publico_fixo = *s;
    }

    if (!cfg.cli_timeout)
    {
        if (const std::string *s = primeiro("timeout"))
        {
            int valor = 0;
            if (numero_config(*s, valor) && valor > 0)
                cfg.timeout_s = valor;
            else
                std::cerr << "invpush: aviso: timeout invalido na configuracao -> "
                          << *s << "\n";
        }
    }

    if (!cfg.cli_janela_boot)
    {
        if (const std::string *s = primeiro("janela-boot"))
        {
            int valor = 0;
            if (numero_config(*s, valor) && valor >= 0)
                cfg.janela_boot_s = valor;
            else
                std::cerr << "invpush: aviso: janela-boot invalida na configuracao -> "
                          << *s << "\n";
        }
    }

    if (!cfg.cli_verificar_tls)
    {
        if (const std::string *s = primeiro("verificar-tls"))
            cfg.verificar_tls = valor_bool(*s, cfg.verificar_tls);
    }
}

// ------------------------------ subcomando config ------------------------------

namespace
{

int cmd_lista()
{
    const NivelConfig g = carregar_nivel(caminho_config_global());
    const std::filesystem::path local_path =
        descobrir_config_local(std::filesystem::current_path());
    const NivelConfig l = carregar_nivel(local_path);

    if (g.vazia() && l.vazia())
    {
        std::cout << "(vazio)\n";
        return EXIT_SUCCESS;
    }

    const NivelConfig efetivo = mesclar_niveis(g, l);
    for (const auto &[chave, valores] : efetivo.entradas)
    {
        const char *origem =
            (l.busca(chave) != nullptr) ? "[local]" : "[global]";
        for (const auto &valor : valores)
            std::cout << origem << " " << chave << "=" << valor << "\n";
    }
    return EXIT_SUCCESS;
}

int usage_erro(const std::string &msg)
{
    std::cerr << msg << "\n\n"
              << "Uso: invpush config [get <chave> | set <chave> <valor...> |\n"
              << "                     add <chave> <valor...> | unset <chave> |\n"
              << "                     list | path]\n"
              << "Escopo de escrita: --global (padrao) | --local (grava ./.invpush.conf)\n"
              << "Chaves: url token maquina ip-publico timeout janela-boot verificar-tls\n"
              << "Atencao: token fica em texto puro no arquivo.\n";
    return EXIT_FAILURE;
}

} // namespace

int comando_config(int argc, char *argv[])
{
    bool escopo_global = true;
    std::vector<std::string> tokens;
    for (int i = 2; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--global")
            escopo_global = true;
        else if (arg == "--local")
            escopo_global = false;
        else
            tokens.push_back(arg);
    }

    const std::string verbo = tokens.empty() ? "list" : tokens[0];

    if (verbo == "list")
    {
        if (tokens.size() > 1)
            return usage_erro("Erro: 'list' nao aceita argumentos.");
        return cmd_lista();
    }

    if (verbo == "path")
    {
        if (tokens.size() > 1)
            return usage_erro("Erro: 'path' nao aceita argumentos.");
        std::cout << "global: " << caminho_config_global().string() << "\n";
        const std::filesystem::path loc =
            descobrir_config_local(std::filesystem::current_path());
        std::cout << "local:  "
                  << (loc.empty() ? std::string("(nenhum)") : loc.string()) << "\n";
        return EXIT_SUCCESS;
    }

    if (verbo == "get")
    {
        if (tokens.size() != 2)
            return usage_erro("Erro: uso correto -> invpush config get <chave>");
        const std::string &chave = tokens[1];
        if (!chave_valida(chave))
            return usage_erro("Erro: chave invalida -> " + chave);

        const NivelConfig g = carregar_nivel(caminho_config_global());
        const NivelConfig l =
            carregar_nivel(descobrir_config_local(std::filesystem::current_path()));
        const NivelConfig efetivo = mesclar_niveis(g, l);

        const auto *valores = efetivo.busca(chave);
        if (valores == nullptr || valores->empty())
        {
            std::cerr << "invpush: chave sem valor -> " << chave << "\n";
            return EXIT_FAILURE;
        }
        for (const auto &valor : *valores)
            std::cout << valor << "\n";
        return EXIT_SUCCESS;
    }

    if (verbo == "set" || verbo == "add" || verbo == "unset")
    {
        if (tokens.size() < 2)
            return usage_erro("Erro: uso correto -> invpush config " + verbo +
                              " <chave> [valores...]");
        const std::string &chave = tokens[1];
        if (!chave_valida(chave))
            return usage_erro("Erro: chave invalida -> " + chave);

        const std::vector<std::string> valores(tokens.begin() + 2, tokens.end());
        if (verbo != "unset" && valores.empty())
            return usage_erro("Erro: informe ao menos um valor para '" + chave + "'.");

        const std::filesystem::path arquivo =
            escopo_global ? caminho_config_global()
                          : std::filesystem::current_path() / NOME_ARQUIVO_LOCAL;
        if (arquivo.empty())
            return usage_erro("Erro: diretorio de configuracao indisponivel.");

        NivelConfig nivel = carregar_nivel(arquivo);
        if (verbo == "set")
            nivel.define(chave, valores);
        else if (verbo == "add")
            nivel.acrescenta(chave, valores);
        else
            nivel.remove(chave);

        if (!salvar_nivel(arquivo, nivel))
        {
            std::cerr << "Erro: falha ao gravar " << arquivo.string() << "\n";
            return EXIT_FAILURE;
        }
        std::cout << (escopo_global ? "[global]" : "[local]") << " " << chave
                  << " gravado em " << arquivo.string() << "\n";
        return EXIT_SUCCESS;
    }

    return usage_erro("Erro: verbo desconhecido -> " + verbo);
}

} // namespace invpush
