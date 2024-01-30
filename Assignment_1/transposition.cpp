#include <iostream>
#include <vector>
using namespace std;

int calc_hash(string s)
{
    int hash = s[0];
    for (int i = 0; i < s.size(); i++)
    {
        hash = hash ^ s[i];
    }
    return hash;
}

string encrypt(vector<int> key, const string &plaintext)
{
    int col = key.size();
    int row = plaintext.size() / col;

    if ((plaintext.size() % col) != 0)
        row += 1;

    char matrix[row][col];

    int k = 0;
    for (int i = 0; i < row; i++)
    {
        for (int j = 0; j < col; j++)
        {
            if (k == plaintext.size())
                break;
            matrix[i][j] = plaintext[k++];
        }
    }
    int val = k % col;
    vector<char> v = {'s', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    int size = v.size();
    for (; val < col; val++)
    {
        matrix[row - 1][val] = v[val - (col - size)];
    }
    // Output the encrypted matrix
    for (int m = 0; m < row; m++)
    {
        for (int n = 0; n < col; n++)
        {
            cout << matrix[m][n] << " ";
        }
        cout << endl;
    }

    // Construct the ciphertext from the matrix
    string ciphertext = "";
    for (int j = 0; j < col; j++)
    {
        for (int i = 0; i < row; i++)
        {
            ciphertext += matrix[i][key[j] - 1];
        }
    }

    return ciphertext;
}

string decrypt(vector<int> key, const string &ciphertext)
{
    int col = key.size();
    int row = ciphertext.size() / col;

    char matrix[row][col];

    int k = 0;
    for (int j = 0; j < col; j++)
    {
        for (int i = 0; i < row; i++)
        {
            matrix[i][key[j] - 1] = ciphertext[k++];
        }
    }

    for (int m = 0; m < row; m++)
    {
        for (int n = 0; n < col; n++)
        {
            cout << matrix[m][n] << " ";
        }
        cout << endl;
    }

    string plaintext = "";
    for (int i = 0; i < row; i++)
    {
        for (int j = 0; j < col; j++)
            plaintext += matrix[i][j];
    }

    return plaintext;
}

int main()
{
    vector<int> key = {3, 1, 4, 2, 5, 6, 7};
    string plaintext = "helloworld";

    // cout << "Enter plaintext: ";
    // getline(cin, plaintext);

    cout << "Plaintext: " << plaintext <<" "<<calc_hash(plaintext)<< endl;

    string ciphertext = encrypt(key, plaintext);
    cout << "Ciphertext: " << ciphertext << endl;

    string decrypted = decrypt(key, ciphertext);

    cout << "Decrypted: " << decrypted <<" "<<calc_hash(decrypted)<< endl;

    return 0;
}
