#include <bits/stdc++.h>
using namespace std;
void solve(int index, vector<vector<int>> &ans, vector<int> &nums, vector<int> &temp)
{
    if (index == nums.size())
    {
        ans.push_back(temp);
        return;
    }

    for (int i = 0; i < nums.size(); i++)
    {
        auto it = find(temp.begin(), temp.end(), nums[i]);
        if (it == temp.end())
        {
            temp.push_back(nums[i]);
            solve(index + 1, ans, nums, temp);
            temp.pop_back();
        }
    }
}
vector<vector<int>> permute(vector<int> nums)
{
    vector<vector<int>> ans;
    vector<int> temp;
    solve(0, ans, nums, temp);
    return ans;
}

unsigned int calc_hash(const std::string &input)
{
    unsigned int hashValue = 0;

    for (char ch : input)
    {
        hashValue ^= static_cast<unsigned int>(ch);       // XOR operation
        hashValue = (hashValue << 5) | (hashValue >> 27); // Bitwise shift
        hashValue += static_cast<unsigned int>(ch);       // Addition
        hashValue *= 31;                                  // Multiplication
    }

    return hashValue;
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

    if (val)
    {
        for (; val < col; val++)
        {
            matrix[row - 1][val] = '#';
        }
    }
    cout << endl;
    for (int i = 0; i < col; i++)
    {
        cout << key[i] << " ";
    }
    cout << endl;
    for (int m = 0; m < row; m++)
    {

        for (int n = 0; n < col; n++)
        {
            cout << matrix[m][n] << " ";
        }
        cout << endl;
    }
    cout << endl;
    unordered_map<int, int> key_map;
    for (int i = 0; i < key.size(); i++)
    {
        key_map[key[i]] = i;
    }

    string ciphertext = "";

    for (int j = 1; j <= key.size(); j++)
    {
        for (int i = 0; i < row; i++)
        {
            ciphertext += matrix[i][key_map[j]];
        }
    }

    return ciphertext;

    // return ciphertext;
}

string decrypt(vector<int> key, const string &ciphertext)
{
    int col = key.size();
    int row = ciphertext.size() / col;

    char matrix[row][col];

    unordered_map<int, int> key_map;
    for (int i = 0; i < key.size(); i++)
    {
        key_map[key[i]] = i;
    }

    int k = 0;
    for (int j = 1; j <= key.size(); j++)
    {
        for (int i = 0; i < row; i++)
        {
            matrix[i][key_map[j]] = ciphertext[k++];
        }
    }

    string plaintext = "";

    for (int i = 0; i < row; i++)
    {
        for (int j = 0; j < col && matrix[i][j] != '#'; j++)
        {
            plaintext += matrix[i][j];
        }
    }

    return plaintext;
}
string remove_padding(string decrypted_msg)
{
    int i = 0;
    for (i = decrypted_msg.size() - 1; i >= 0; i--)
    {
        if (decrypted_msg[i] != '#')
            break;
    }
    return decrypted_msg.substr(0, i + 1);
}
void print_keyset(const std::vector<std::vector<int>> &keySet)
{
    for (auto key : keySet)
    {
        for (int element : key)
        {
            cout << element;
        }
        cout << " ";
    }
    cout << endl;
}
bool check_all_ciphertexts(vector<int> transposition_key, vector<string> ciphertexts_vec, vector<string> plaintexts_vec)
{
    for (int i = 1; i < plaintexts_vec.size(); i++)
    {
        string decrypted_msg = decrypt(transposition_key, ciphertexts_vec[i]);
        string final_decrypted = remove_padding(decrypted_msg);
        cout << "Decrypted:" << final_decrypted << "\n"
             << "Decrypted hash:" << calc_hash(final_decrypted) << " " << endl;
        if (calc_hash(final_decrypted) != calc_hash(plaintexts_vec[i]))
            return false;
    }
    return true;
}
vector<int> brute_force(vector<string> ciphertexts_vec, vector<string> plaintexts_vec)
{
    vector<int> discover_key = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    for (int i = 1; i < 10; i++)
    {
        if (ciphertexts_vec[0].size() % i != 0)
            continue;
        vector<int> key_elements(discover_key.begin(), discover_key.begin() + i);
        vector<vector<int>> key_set = permute(key_elements);

        for (auto transposition_key : key_set)
        {
            string decrypted_msg = decrypt(transposition_key, ciphertexts_vec[0]);
            string final_decrypted = remove_padding(decrypted_msg);

            if (calc_hash(final_decrypted) != calc_hash(plaintexts_vec[0]))
                continue;
            else
            {
                if (check_all_ciphertexts(transposition_key, ciphertexts_vec, plaintexts_vec) == true)
                    return transposition_key;
            }
        }
    }
    cout << " KEY NOT FOUND" << endl;
    return {-1};
}
int main()
{
    vector<int> key = {3, 1, 4, 2, 5, 6, 7};
    // string plaintext = "helloworld";

    vector<string> plaintexts_vec;
    for (int i = 0; i < 5; i++)
    {
        string plaintext;
        cin >> plaintext;
        plaintexts_vec.push_back(plaintext);
    }
    for (auto plaintext : plaintexts_vec)
        cout << "Plaintext: " << plaintext << "\n"
             << "Plaintext Hash: " << calc_hash(plaintext) << endl;

    vector<string> ciphertexts_vec;
    vector<string> decrypted_vec;
    for (auto plaintext : plaintexts_vec)
    {
        ciphertexts_vec.push_back(encrypt(key, plaintext));
    }
    for (auto ciphertext : ciphertexts_vec)
    {
        cout << "Ciphertext: " << ciphertext << endl;
    }
    for (auto ciphertext : ciphertexts_vec)
    {
        decrypted_vec.push_back(decrypt(key, ciphertext));
    }

    vector<int> discovered_key = brute_force(ciphertexts_vec, plaintexts_vec);
    cout << "Discovered key: ";
    for (auto it : discovered_key)
    {
        cout << it << " ";
    }
    cout << endl;

    return 0;
}
