//
// Created by Jiaqi Xue on 2/5/23.
//
#include <algorithm>
#include <ctime>
#include <string>
#include <vector>
#include "examples.h"

using namespace std;
using namespace seal;

class BGV {
private:
    int rol_a, col_a;
    int blind;

    void print_matrix(vector<vector<uint64_t>> matrix, bool T = false) {
        if (T) {
            for (int i = 0; i < matrix[0].size(); i++) {
                for (int j = 0; j < matrix.size(); j++)
                    cout << matrix[j][i] << " ";
                cout << endl;
            }
            cout << "==========================" << endl;
        } else {
            for (int i = 0; i < matrix.size(); i++) {
                for (int j = 0; j < matrix[i].size(); j++)
                    cout << matrix[i][j] << " ";
                cout << endl;
            }
            cout << "==========================" << endl;
        }
    }

    void print_vector(vector<uint64_t> vec) {
        for (int i = 0; i < vec.size(); i++)
            cout << vec[i] << " ";
        cout << endl << "==========================" << endl;
    }

    bool matrix_equal(vector<vector<uint64_t>> a, vector<vector<uint64_t>> b) {
        if (a == b)
            return true;
        else
            return false;
    }

    vector<vector<uint64_t>> matrix_mul(vector<vector<uint64_t>> a, vector<vector<uint64_t>> b) {
        int rol = a.size();
        int col = b.size();
        vector<vector<uint64_t>> res(rol, vector<uint64_t>(col));
        for (int i = 0; i < rol; i++) {
            for (int j = 0; j < col; j++) {
                int sum = 0;
                for (int k = 0; k < a[0].size(); k++)
                    sum += a[i][k] * b[j][k];
                res[i][j] = sum;
            }
        }
        return res;
    }

    vector<uint64_t> vector_mul_matrix(vector<uint64_t> a, vector<vector<uint64_t>> b, int shit) {
        vector<uint64_t> res(a.size(), 0);
        if(shit){
            for (int j = 0; j < b[0].size(); j++) {
                for (int i = 0; i < b.size(); i++) {
                    uint64_t temp = b[i][j];
                    temp << a[i];
                    res[j] += temp;
                }
            }
        }
        else{
            for (int j = 0; j < b[0].size(); j++) {
                for (int i = 0; i < b.size(); i++)
                    res[j] += a[i] * b[i][j];
            }
        }
        return res;
    }

    vector<vector<uint64_t>> init_message(int N, int seed) {
        srand(seed);
        vector<vector<uint64_t>> res(N, vector<uint64_t>(N));
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++)
                res[i][j] = rand() % 10 + 1;
        }
        return res;
    }

    vector<uint64_t> gen_check(int length, int seed) {
        srand(seed);
        vector<uint64_t> check(length);
        generate(check.begin(), check.end(), []() {
            return rand() % 11; // generates a random number between 0 and 10
        });
        return check;
    }

    string verification(vector<uint64_t> check, vector<vector<uint64_t>> message, int shift) {
        vector<uint64_t> message_tail = message.back();
        message.pop_back();
        bool ver = (message_tail == vector_mul_matrix(check, message, shift));
        if (ver)
            return "yes";
        else
            return "no";
    }

    Ciphertext
    matrix_to_ciphertext(vector<vector<uint64_t>> message, BatchEncoder &batch_encoder, Encryptor &encryptor) {
        // flatten 2d message to 1d
        vector<uint64_t> message_1d;
        for (int i = 0; i < message.size(); i++) {
            for (int j = 0; j < message[i].size(); j++)
                message_1d.push_back(message[i][j]);
        }

        // convert message to plaintext
        Plaintext plaintext_res;
        batch_encoder.encode(message_1d, plaintext_res);

        // convert plaintext to ciphertext
        Ciphertext ciphertext_res;
        encryptor.encrypt(plaintext_res, ciphertext_res);

        return ciphertext_res;
    }

    Ciphertext server_compute_col(
            Ciphertext ciphertext_a, vector<uint64_t> message_b_i, int rol_a, BatchEncoder &batch_encoder,
            Evaluator &evaluator, GaloisKeys galois_keys) {
        Ciphertext ciphertext_v = ciphertext_a;
        vector<uint64_t> message_b_i_extend(rol_a * message_b_i.size(), 0);
        for (int i = 0; i < rol_a; i++) {
            for (int j = 0; j < message_b_i.size(); j++)
                message_b_i_extend[i * message_b_i.size() + j] = message_b_i[j];
        }

        Plaintext plaintext_b_i_extend;
        batch_encoder.encode(message_b_i_extend, plaintext_b_i_extend);
        evaluator.multiply_plain_inplace(ciphertext_v, plaintext_b_i_extend);

        int length = message_b_i.size();
        Ciphertext one;
        Ciphertext ciphertext_v1 = ciphertext_v;
        bool flag = false;
        while (length > 1) {
            Ciphertext ciphertext_v2 = ciphertext_v1;
            evaluator.rotate_rows_inplace(ciphertext_v2, length / 2, galois_keys);
            evaluator.add(ciphertext_v2, ciphertext_v1, ciphertext_v1);
            if (length % 2) {
                evaluator.rotate_rows_inplace(ciphertext_v2, length / 2, galois_keys);
                if (!flag) {
                    one = ciphertext_v2;
                    flag = true;
                } else
                    evaluator.add(one, ciphertext_v2, one);
            }
            length /= 2;
        }
        if (flag)
            evaluator.add(one, ciphertext_v1, ciphertext_v1);
        return ciphertext_v1;
    }

    vector<Ciphertext> server_compute(
            Ciphertext ciphertext_a, vector<vector<uint64_t>> message_b, int rol_a, BatchEncoder &batch_encoder,
            Evaluator &evaluator, GaloisKeys galois_keys) {
        vector<Ciphertext> cipher_matrix(message_b.size());
        for (int i = 0; i < message_b.size(); i++)
            cipher_matrix[i] =
                    server_compute_col(ciphertext_a, message_b[i], rol_a, batch_encoder, evaluator, galois_keys);
        return cipher_matrix;
    }

    vector<vector<uint64_t>> client_decrypt(
            vector<Ciphertext> cipher_matrix, Decryptor &decryptor, BatchEncoder &batch_encoder, int rol, int col) {
        vector<vector<uint64_t>> message_result(rol, vector<uint64_t>(col));
        for (int i = 0; i < cipher_matrix.size(); i++) {
            Plaintext plain_col_i;
            decryptor.decrypt(cipher_matrix[i], plain_col_i);
            vector<uint64_t> message_col_i;
            batch_encoder.decode(plain_col_i, message_col_i);
            for (int j = 0; j < rol; j++)
                message_result[j][i] = message_col_i[j * col];
        }
        return message_result;
    }

public:
    BGV(int N, int blind) {
        this->blind = blind;
        if (blind)
            rol_a = N + 1;
        else
            rol_a = N;
        col_a = N;
    }

    void experiment(int flops, int log_epoch, int validation, int shift) {
        // log
        string log_name = "bgv/" + to_string(rol_a) + 'x' + to_string(col_a);
        if(shift)
            log_name += "_shift";
        log_name += ".log";
        freopen(log_name.c_str(), "w", stdout);

        // init context
        EncryptionParameters parms(scheme_type::bgv);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
        SEALContext context(parms);

        // init encryptor, evaluator, decryptor
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);

        // init rotation key
        GaloisKeys galois_keys;
        keygen.create_galois_keys(galois_keys);

        // init batch encoder
        BatchEncoder batch_encoder(context);

        // experiments
        double server_time = 0.0;
        double client_enc_time = 0.0;
        double client_dec_time = 0.0;
        double client_prepare_time = 0.0;
        double client_verification_time = 0.0;

        double cache = 0.0;
        clock_t client_enc_start, client_enc_end;
        clock_t client_dec_start, client_dec_end;
        clock_t server_start, server_end;
        clock_t client_prepare_start, client_prepare_end;
        clock_t client_verification_start, client_verification_end;

        for (int i = 0; i < flops; i++) {
            // init message
            srand(unsigned(time(nullptr)));
            vector<vector<uint64_t>> message_a = init_message(col_a, rand());
            vector<vector<uint64_t>> message_b = init_message(col_a, rand());

            // prepare
            client_prepare_start = clock();
            vector<uint64_t> check = gen_check(message_a.size(), rand());
            message_a.push_back(vector_mul_matrix(check, message_a, shift));
            client_prepare_end = clock();
            client_prepare_time += double(client_prepare_end - client_prepare_start) / CLOCKS_PER_SEC;

            // client a: convert message a to ciphertext
            client_enc_start = clock();
            Ciphertext ciphertext_a = matrix_to_ciphertext(message_a, batch_encoder, encryptor);
            client_enc_end = clock();
            client_enc_time += double(client_enc_end - client_enc_start) / CLOCKS_PER_SEC;
            cache += sizeof(ciphertext_a) / (1024.0 * 1024.0);

            // server: compute
            server_start = clock();
            vector<Ciphertext> cipher_res =
                    server_compute(ciphertext_a, message_b, rol_a, batch_encoder, evaluator, galois_keys);
            server_end = clock();
            server_time += double(server_end - server_start) / CLOCKS_PER_SEC;

            // client a: decrypt
            cache += sizeof(cipher_res) / (1024.0 * 1024.0);
            client_dec_start = clock();
            vector<vector<uint64_t>> message_res = client_decrypt(cipher_res, decryptor, batch_encoder, rol_a, col_a);
            client_dec_end = clock();
            client_dec_time += double(client_dec_end - client_dec_start) / CLOCKS_PER_SEC;

            // verification
            string ver = "";
            if (blind) {
                client_verification_start = clock();
                ver = verification(check, message_res, shift);
                client_verification_end = clock();
                client_verification_time +=
                        double(client_verification_end - client_verification_start) / CLOCKS_PER_SEC;
            }

            if ((i + 1) % log_epoch == 0) {
                if (validation && blind)
                    cout << "[" << i + 1 << "|" << flops << "] [" << client_prepare_time << "|" << client_enc_time
                         << "|" << client_dec_time << "|" << client_verification_time << "] [" << server_time
                         << "|" << cache << "] [" << ver << "]" << endl;
                else if (blind)
                    cout << "[" << i + 1 << "|" << flops << "] [" << client_prepare_time << "|" << client_enc_time
                         << "|" << client_dec_time << "|" << client_verification_time << "] [" << server_time
                         << "|" << cache << "]" << endl;
                else {
                    cout << "[" << i + 1 << "|" << flops << "] [" << client_enc_time << "|" << client_dec_time << "|"
                         << server_time << "|" << cache << "]" << endl;
                }
            }
        }
    }
};

void experiment_bgv(int N, int blind, int flops, int log_epoch, int validation, int shift) {
    BGV bgv(N, blind);
    bgv.experiment(flops, log_epoch, validation, shift);
}
