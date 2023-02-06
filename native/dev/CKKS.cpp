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

class CKKS
{
private:
    int rol_a, col_a;
    void print_matrix(vector<vector<double>> matrix, bool T = false)
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
    void print_vector(vector<double> vec)
    {
        for (int i = 0; i < vec.size(); i++)
            cout << vec[i] << " ";
        cout << endl << "==========================" << endl;
    }
    bool matrix_equal(vector<vector<double>> a, vector<vector<double>> b)
    {
        for (int i = 0; i < a.size(); i++)
        {
            for (int j = 0; j < a[i].size(); j++)
            {
                if (abs(a[i][j] - b[i][j]) > 1)
                    return false;
            }
        }
        return true;
    }
    vector<vector<double>> matrix_mul(vector<vector<double>> a, vector<vector<double>> b)
    {
        int rol = a.size();
        int col = b.size();
        vector<vector<double>> res(rol, vector<double>(col));
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
    vector<vector<double>> init_message(int N, int M, int seed)
    {
        srand(seed);
        vector<vector<double>> res(N, vector<double>(M));
        for (int i = 0; i < N; i++)
        {
            for (int j = 0; j < M; j++)
                res[i][j] = (rand() % 99) / 9.0 + 0.5;
        }
        return res;
    }
    Ciphertext matrix_to_ciphertext(
        vector<vector<double>> message, CKKSEncoder &batch_encoder, double scale, Encryptor &encryptor)
    {
        // flatten 2d message to 1d
        vector<double> message_1d;
        for (int i = 0; i < message.size(); i++)
        {
            for (int j = 0; j < message[i].size(); j++)
                message_1d.push_back(message[i][j]);
        }

        // convert message to plaintext
        Plaintext plaintext_res;
        batch_encoder.encode(message_1d, scale, plaintext_res);

        // convert plaintext to ciphertext
        Ciphertext ciphertext_res;
        encryptor.encrypt(plaintext_res, ciphertext_res);

        return ciphertext_res;
    }
    Ciphertext server_compute_col(
        Ciphertext ciphertext_a, vector<double> message_b_i, int rol_a, CKKSEncoder &batch_encoder, double scale,
        Evaluator &evaluator, GaloisKeys galois_keys)
    {
        Ciphertext ciphertext_v = ciphertext_a;
        vector<double> message_b_i_extend(rol_a * message_b_i.size(), 0);
        for (int i = 0; i < rol_a; i++)
        {
            for (int j = 0; j < message_b_i.size(); j++)
                message_b_i_extend[i * message_b_i.size() + j] = message_b_i[j];
        }

        Plaintext plaintext_b_i_extend;
        batch_encoder.encode(message_b_i_extend, scale, plaintext_b_i_extend);
        evaluator.multiply_plain_inplace(ciphertext_v, plaintext_b_i_extend);

        int length = message_b_i.size();
        Ciphertext one;
        Ciphertext ciphertext_v1 = ciphertext_v;
        bool flag = false;
        while (length > 1)
        {
            Ciphertext ciphertext_v2 = ciphertext_v1;
            evaluator.rotate_vector(ciphertext_v2, length / 2, galois_keys, ciphertext_v2);
            evaluator.add(ciphertext_v2, ciphertext_v1, ciphertext_v1);
            if (length % 2)
            {
                evaluator.rotate_vector(ciphertext_v2, length / 2, galois_keys, ciphertext_v2);
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
        Ciphertext ciphertext_a, vector<vector<double>> message_b, int rol_a, CKKSEncoder &batch_encoder, double scale,
        Evaluator &evaluator, GaloisKeys galois_keys)
    {
        vector<Ciphertext> cipher_matrix(message_b.size());
        for (int i = 0; i < message_b.size(); i++)
            cipher_matrix[i] =
                server_compute_col(ciphertext_a, message_b[i], rol_a, batch_encoder, scale, evaluator, galois_keys);
        return cipher_matrix;
    }
    vector<vector<double>> client_decrypt(
        vector<Ciphertext> cipher_matrix, Decryptor &decryptor, CKKSEncoder &batch_encoder, int rol, int col)
    {
        vector<vector<double>> message_result(rol, vector<double>(col));
        for (int i = 0; i < cipher_matrix.size(); i++)
        {
            Plaintext plain_col_i;
            decryptor.decrypt(cipher_matrix[i], plain_col_i);
            vector<double> message_col_i;
            batch_encoder.decode(plain_col_i, message_col_i);
            for (int j = 0; j < rol; j++)
                message_result[j][i] = message_col_i[j * col];
        }
        return message_result;
    }

public:
    CKKS(int rol_a, int col_a)
    {
        this->rol_a = rol_a;
        this->col_a = col_a;
    }
    void experiment(int flops, int log_epoch, int validation)
    {
        // log
        string log_name = "ckks/" + to_string(rol_a) + 'x' + to_string(col_a) + ".log";
        freopen(log_name.c_str(), "w", stdout);

        // init context
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        double scale = pow(2.0, 40);
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
        CKKSEncoder batch_encoder(context);

        // experiments
        double client_time = 0;
        double server_time = 0;
        clock_t client_start, client_end, server_start, server_end;

        for (int i = 0; i < flops; i++)
        {
            // init message
            srand(unsigned(time(nullptr)));
            vector<vector<double>> message_a = init_message(rol_a, col_a, rand());
            vector<vector<double>> message_b = init_message(col_a, col_a, rand());

            // client a: convert message a to ciphertext
            client_start = clock();
            Ciphertext ciphertext_a = matrix_to_ciphertext(message_a, batch_encoder, scale, encryptor);

            // server: compute
            server_start = clock();
            vector<Ciphertext> cipher_res =
                server_compute(ciphertext_a, message_b, rol_a, batch_encoder, scale, evaluator, galois_keys);
            server_end = clock();
            server_time += double(server_end - server_start) / CLOCKS_PER_SEC;

            // client a: decrypt
            vector<vector<double>> message_res = client_decrypt(cipher_res, decryptor, batch_encoder, rol_a, col_a);
            client_end = clock();
            client_time += double(client_end - client_start) / CLOCKS_PER_SEC;

            if ((i + 1) % log_epoch == 0)
            {
                if (validation == 0)
                    cout << "[" << i + 1 << "|" << flops << "] [" << server_time << "|" << client_time << "]" << endl;
                else
                {
                    vector<vector<double>> ans = matrix_mul(message_a, message_b);
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

void experiment_ckks(int rol_a, int col_a, int flops, int log_epoch, int validation)
{
    CKKS ckks(rol_a, col_a);
    ckks.experiment(flops, log_epoch, validation);
}