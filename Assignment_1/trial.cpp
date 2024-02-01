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
unsigned int jenkins_hash(const std::string &input)
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

// unsigned int jenkins_hash(const string& plaintext) {
//     unsigned int hash = 0;

//     for (char character : plaintext) {
//         hash += static_cast<unsigned int>(character);
//         hash += (hash << 10);
//         hash ^= (hash >> 6);
//     }

//     hash += (hash << 3);
//     hash ^= (hash >> 11);
//     hash += (hash << 15);

//     return hash;
// }

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
    int padding = k % col;

    if (padding)
    {
        for (; padding < col; padding++)
        {
            matrix[row - 1][padding] = 'z';
        }
    }
    // cout << endl;
    // for (int i = 0; i < col; i++)
    // {
    //     cout << key[i] << " ";
    // }
    // cout << endl;
    // for (int m = 0; m < row; m++)
    // {

    //     for (int n = 0; n < col; n++)
    //     {
    //         cout << matrix[m][n] << " ";
    //     }
    //     cout << endl;
    // }
    // cout << endl;
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
        if (decrypted_msg[i] != 'z')
            break;
    }
    return decrypted_msg.substr(0, i + 1);
}
string remove_zeros(string hash_20bits)
{
    int i = 0;
    for (i = 0; i <hash_20bits.size(); i++)
    {
        if (hash_20bits[i] != '0')
            break;
    }
    return hash_20bits.substr(i,hash_20bits.size()-i);
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
bool check_all_ciphertexts(vector<int> transposition_key, vector<string> ciphertexts_vec)
{
    map<char, char> Alp_Num = {{'a', '0'}, {'b', '1'}, {'c', '2'}, {'d', '3'}, {'e', '4'}, {'f', '5'}, {'g', '6'}, {'h', '7'}, {'i', '8'}, {'j', '9'}};
    for (int i = 1; i < ciphertexts_vec.size(); i++)
    {
    string decrypted_msg = decrypt(transposition_key, ciphertexts_vec[i]);
    string final_decrypted = remove_padding(decrypted_msg);
            
    if(final_decrypted.size()<=20){
                return false;
    }
    string decrypted_without_hash=final_decrypted.substr(0,final_decrypted.size()-20);
    string hash_value_alp=final_decrypted.substr(final_decrypted.size()-20);
    string hash_value_num="";
    for(auto it : hash_value_alp){
        hash_value_num+=Alp_Num[it];
        }
    cout<< final_decrypted<< " "<< decrypted_without_hash<< " "<< remove_zeros(hash_value_num)<< endl;
    if (to_string(jenkins_hash(decrypted_without_hash)) != remove_zeros(hash_value_num)){
        return false;
    }
    }
    return true;
}
vector<int> brute_force(vector<string> ciphertexts_vec)
{
    vector<int> discover_key = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    map<char, char> Alp_Num = {{'a', '0'}, {'b', '1'}, {'c', '2'}, {'d', '3'}, {'e', '4'}, {'f', '5'}, {'g', '6'}, {'h', '7'}, {'i', '8'}, {'j', '9'}};
    for (int i = 1; i < 10; i++)
    {  
        if (ciphertexts_vec[0].size() % i != 0)
            continue;
        vector<int> key_elements(discover_key.begin(), discover_key.begin() + i);
        vector<vector<int>> key_set = permute(key_elements);
 
        // print_keyset(key_set);
        for (auto transposition_key : key_set)
        {
            string decrypted_msg = decrypt(transposition_key, ciphertexts_vec[0]);
            string final_decrypted = remove_padding(decrypted_msg);
            
            if(final_decrypted.size()<=20){
                continue;
            }
            string decrypted_without_hash=final_decrypted.substr(0,final_decrypted.size()-20);
            string hash_value_alp=final_decrypted.substr(final_decrypted.size()-20);
            string hash_value_num="";
            for(auto it : hash_value_alp){
                hash_value_num+=Alp_Num[it];
            }

            if (to_string(jenkins_hash(decrypted_without_hash)) != remove_zeros(hash_value_num))
                continue;
            else
            {   
                cout<< final_decrypted<< " "<< decrypted_without_hash<< " "<< remove_zeros(hash_value_num)<< endl;
                if (check_all_ciphertexts(transposition_key, ciphertexts_vec) == true)
                    return transposition_key;
            }
        }
    }
    cout << " KEY NOT FOUND" << endl;
    return {-1};
}
string plain_hash_concatenation(const string& plaintext) {
    map<int, char> Num_Alp;
    for (int i = 0; i <= 9; ++i) {
        Num_Alp[i] = 'a' + i;
    }

    unsigned int hash_value = jenkins_hash(plaintext);
    
    string hash_converted = "";

    // Ensure the hash value has at least 20 digits
    string hash_str = to_string(hash_value);
    hash_str = string(20 - hash_str.length(), '0') + hash_str; // Pad with zeros to the left

for (char digit : hash_str) {
    hash_converted += Num_Alp[digit - '0'];
}
      cout<<"Plaintext: "<<  plaintext<<" "<<hash_converted<<  " "<< hash_value<< endl;
    return plaintext + hash_converted;
}
int main()
{
    vector<int> key = {3, 1, 4, 2,5,6,7};
  

    vector<string> plaintexts_vec;
    
    for (int i = 0; i < 2; i++)
    {
        string plaintext;
        cout<< "Enter Plaintext_"<< i+1<< ":";
        cin >> plaintext;
        plaintexts_vec.push_back(plain_hash_concatenation(plaintext));
    }
    
    // for(auto it: plaintexts_vec){
      
    // }

    vector<string> ciphertexts_vec;
    for (auto plaintext : plaintexts_vec)
    {
        ciphertexts_vec.push_back(encrypt(key, plaintext));
    }
    // for (auto ciphertext : ciphertexts_vec)
    // {
    //     cout << "Ciphertext: " << ciphertext << endl;
    // }
    for(auto it : ciphertexts_vec){
        cout<< " decrpyted : "<< decrypt(key,it)<< endl;
    }

    vector<int> discovered_key = brute_force(ciphertexts_vec);
    cout << "Discovered key: ";
    for (auto it : discovered_key)
    {
        cout << it << " ";
    }
    cout << endl;

    return 0;
}
