#include "invpush.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char *argv[])
{
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

    invpush::apply_env(cfg);

    return invpush::run(cfg);
}
