#include "invpush.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char *argv[])
{
    // Subcomando de configuração persistente (estilo git config).
    if (argc > 1 && std::string(argv[1]) == "config")
        return invpush::comando_config(argc, argv);

    invpush::Config cfg;
    if (!invpush::parse_args(argc, argv, cfg))
    {
        invpush::print_help(argv[0]);
        return EXIT_FAILURE;
    }

    if (cfg.ajuda)
    {
        invpush::print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    if (cfg.versao)
    {
        std::cout << "invpush v" << INVPUSH_VERSION << "\n";
        return EXIT_SUCCESS;
    }

    // Precedência: CLI > .invpush.conf local > config global > env > padrões.
    invpush::apply_env(cfg);
    const invpush::NivelConfig global =
        invpush::carregar_nivel(invpush::caminho_config_global());
    const std::filesystem::path local_path =
        invpush::descobrir_config_local(std::filesystem::current_path());
    const invpush::NivelConfig local = invpush::carregar_nivel(local_path);
    invpush::aplicar_config(cfg, invpush::mesclar_niveis(global, local));

    return invpush::run(cfg);
}
