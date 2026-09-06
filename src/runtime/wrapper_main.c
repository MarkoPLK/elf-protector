#ifndef EMBEDDED_PAYLOAD_HEADER
#error "EMBEDDED_PAYLOAD_HEADER debe definirse al compilar el wrapper"
#endif

#ifndef PROTECTED_PAYLOAD_SYMBOL
#error "PROTECTED_PAYLOAD_SYMBOL debe definirse al compilar el wrapper"
#endif

#include <stdlib.h>

#include "runtime_core.h"

#include EMBEDDED_PAYLOAD_HEADER

int main(int argc, char **argv)
{
    int rc = wrapper_execute_blob(&PROTECTED_PAYLOAD_SYMBOL, argc, argv);
    return rc >= 0 ? rc : EXIT_FAILURE;
}
