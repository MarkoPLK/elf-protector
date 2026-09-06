#ifndef RUNTIME_CORE_H
#define RUNTIME_CORE_H

#include "wrapper_blob.h"

int wrapper_verify_blob_integrity(const struct wrapper_embedded_blob *blob);
int wrapper_execute_blob(const struct wrapper_embedded_blob *blob,
                         int argc,
                         char **argv);

#endif
