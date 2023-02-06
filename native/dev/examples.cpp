// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main() {
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    cout << "validation: ";
    int validation;
    cin >> validation;

    cout << "flops: ";
    int flops;
    cin >> flops;

    cout << "log_epoch: ";
    int log_epoch;
    cin >> log_epoch;

    for (int N = 1; N <= 64; N++)
        experiment_ckks(N, N, flops, log_epoch, 0);
    for (int N = 2; N <= 64; N++)
        experiment_ckks(N, N - 1, flops, log_epoch, 0);

    for (int N = 1; N <= 64; N++)
        experiment_bgv(N, N, flops, log_epoch, validation);
    for (int N = 2; N <= 64; N++)
        experiment_bgv(N, N - 1, flops, log_epoch, validation);

    for (int N = 1; N <= 64; N++)
        experiment_bfv(N, N, flops, log_epoch, validation);
    for (int N = 2; N <= 64; N++)
        experiment_bfv(N, N - 1, flops, log_epoch, validation);
    return 0;
}