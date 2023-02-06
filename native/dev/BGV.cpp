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

class BGV
{
private:
    int rol_a, col_a;
    void print_matrix(vector<vector<uint64_t>> matrix, bool T = false)
    {
        if (T)
        {
            for (int i = 0; i < matrix[0].size(); i++)
            {
                for (int j = 0; j < matrix.size(); j++)
                    cout << matrix[j][i] << " ";
                cout << endl;
            }
            cout << "==========================" << endl;
        }
        else
        {
            for (int i = 0; i < matrix.size(); i++)
            {
                for (int j = 0; j < matrix[i].size(); j++)
                    cout << matrix[i][j] << " ";
                cout << endl;
            }
            cout << "==========================" << endl;
        }
    }
    void print_vector(vector<uint64_t> vec)
    {
        for (int i = 0; i < vec.size(); i++)
            cout << vec[i] << " ";
        cout << endl << "==========================" << endl;
    }
    bool matrix_equal(vector<vector<uint64_t>> a, vector<vector<uint64_t>> b)
    {
        if (a == b)
            return true;
        else
            return false;
    }
    vector<vector<uint64_t>> matrix_mul(vector<vector<uint64_t>> a, vector<vector<uint64_t>> b)
    {
        int rol = a.size();
        int col = b.size();
        vector<vector<uint64_t>> res(rol, vector<uint64_t>(col));
        for (int i = 0; i < rol; i++)
        {
            for (int j = 0; j < col; j++)
            {
                int sum = 0;
                for (int k = 0; k < a[0].size(); k++)
                    sum += a[i][k] * b[j][k];
                res[i][j] = sum;
            }
        }
        return res;
    }
    vector<vector<uint64_t>> init_message(int N, int M, int seed)
    {
        srand(seed);
        vector<vector<uint64_t>> res(N, vector<uint64_t>(M));
        for (int i = 0; i < N; i++)
        {
            for (int j = 0; j < M; j++)
                res[i][j] = rand() % 10 + 1;
        }
        return res;
    }
    Ciphertext matrix_to_ciphertext(vector<vector<uint64_t>> message, BatchEncoder &batch_encoder, Encryptor &encryptor)
    {
        // flatten 2d message to 1d
        vector<uint64_t> message_1d;
        for (int i = 0; i < message.size(); i++)
        {
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
        Evaluator &evaluator, GaloisKeys galois_keys)
    {
        Ciphertext ciphertext_v = ciphertext_a;
        vector<uint64_t> message_b_i_extend(rol_a * message_b_i.size(), 0);
        for (int i = 0; i < rol_a; i++)
        {
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
        while (length > 1)
        {
            Ciphertext ciphertext_v2 = ciphertext_v1;
            evaluator.rotate_rows_inplace(ciphertext_v2, length / 2, galois_keys);
            evaluator.add(ciphertext_v2, ciphertext_v1, ciphertext_v1);
            if (length % 2)
            {
                evaluator.rotate_rows_inplace(ciphertext_v2, length / 2, galois_keys);
                if (!flag)
                {
                    one = ciphertext_v2;
                    flag = true;
                }
                else
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
        Evaluator &evaluator, GaloisKeys galois_keys)
    {
        vector<Ciphertext> cipher_matrix(message_b.size());
        for (int i = 0; i < message_b.size(); i++)
            cipher_matrix[i] =
                server_compute_col(ciphertext_a, message_b[i], rol_a, batch_encoder, evaluator, galois_keys);
        return cipher_matrix;
    }
    vector<vector<uint64_t>> client_decrypt(
        vector<Ciphertext> cipher_matrix, Decryptor &decryptor, BatchEncoder &batch_encoder, int rol, int col)
    {
        vector<vector<uint64_t>> message_result(rol, vector<uint64_t>(col));
        for (int i = 0; i < cipher_matrix.size(); i++)
        {
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
    BGV(int rol_a, int col_a)
    {
        this->rol_a = rol_a;
        this->col_a = col_a;
    }
    void experiment(int flops, int log_epoch, int validation)
    {
        // log
        string log_name = "bgv/" + to_string(rol_a) + 'x' + to_string(col_a) + ".log";
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
        double client_time = 0;
        double server_time = 0;
        clock_t client_start, client_end, server_start, server_end;

        for (int i = 0; i < flops; i++)
        {
            // init message
            srand(unsigned(time(nullptr)));
            vector<vector<uint64_t>> message_a = init_message(rol_a, col_a, rand());
            vector<vector<uint64_t>> message_b = init_message(col_a, col_a, rand());

            // client a: convert message a to ciphertext
            client_start = clock();
            Ciphertext ciphertext_a = matrix_to_ciphertext(message_a, batch_encoder, encryptor);

            // server: compute
            server_start = clock();
            vector<Ciphertext> cipher_res =
                server_compute(ciphertext_a, message_b, rol_a, batch_encoder, evaluator, galois_keys);
            server_end = clock();
            server_time += double(server_end - server_start) / CLOCKS_PER_SEC;

            // client a: decrypt
            vector<vector<uint64_t>> message_res = client_decrypt(cipher_res, decryptor, batch_encoder, rol_a, col_a);
            client_end = clock();
            client_time += double(client_end - client_start) / CLOCKS_PER_SEC;

            if ((i + 1) % log_epoch == 0)
            {
                if (validation == 0)
                    cout << "[" << i + 1 << "|" << flops << "] [" << server_time << "|" << client_time << "]" << endl;
                else
                {
                    vector<vector<uint64_t>> ans = matrix_mul(message_a, message_b);
                    string val;
                    if (matrix_equal(ans, message_res))
                        val = "correct";
                    else
                        val = "wrong";
                    cout << "[" << i + 1 << "|" << flops << "] [" << server_time << "|" << client_time << "]: " << val
                         << endl;
                }
            }
        }
    }
};

void experiment_bgv(int rol_a, int col_a, int flops, int log_epoch, int validation)
{
    BGV bgv(rol_a, col_a);
    bgv.experiment(flops, log_epoch, validation);
}
