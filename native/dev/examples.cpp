// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main() {
	experiment_bgv(64, 0, 500, 100, 0, 0, 0);
    experiment_bgv(64, 1, 500, 100, 0, 0, 0);
//    experiment_bgv(64, 1, 500, 100, 0, 1, 0);
//    experiment_bgv(64, 0, 500, 100, 0, 0, 1);
//    experiment_bgv(64, 1, 500, 100, 0, 0, 1);
    return 0;
}