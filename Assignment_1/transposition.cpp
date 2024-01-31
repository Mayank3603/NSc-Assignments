#include <bits/stdc++.h>
using namespace std;
void solve(int index,vector<vector<int>> & ans,vector<int> & nums, vector<int> &temp){
    if(index==nums.size()){
        ans.push_back(temp);
        return;
    }
        
    for(int i=0;i<nums.size();i++){
            auto it =find(temp.begin(), temp.end(), nums[i]);
            if(it==temp.end()){
            temp.push_back(nums[i]);
            solve(index+1,ans,nums,temp);
            temp.pop_back();
            }
            
    }
}
vector<vector<int>> permute(vector<int> nums) {
    vector<vector<int>> ans;
    vector<int> temp;
    solve(0,ans,nums,temp);
    return ans;
}
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
    // vector<char> v = {'s', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    // int size = v.size();
    // for (; val < col; val++)
    // {
    //     matrix[row - 1][val] = v[val - (col - size)];
    // }
     for (; val < col; val++)
    {
        matrix[row - 1][val] = '#';
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

    // for (int m = 0; m < row; m++)
    // {
    //     for (int n = 0; n < col; n++)
    //     {
    //         cout << matrix[m][n] << " ";
    //     }
    //     cout << endl;
    // }

    string plaintext = "";
    for (int i = 0; i < row; i++)
    {
        for (int j = 0; j < col; j++)
            plaintext += matrix[i][j];
    }

    return plaintext;
}
string remove_padding(string decrypted_msg){
    int i=0;
    for(i=decrypted_msg.size()-1;i>=0;i--){
        if(decrypted_msg[i]!='#') break;
    }
    return decrypted_msg.substr(0,i+1);
}
void print_keyset(const std::vector<std::vector<int>>& keySet) {
    for (auto key : keySet) {
        for (int element : key) {
            cout << element ;
        }
        cout<< " ";
    }
    cout<< endl;
}
bool check_all_ciphertexts(vector<int> transposition_key,vector<string> ciphertexts_vec,vector<string> plaintexts_vec){
    for(int i=0;i<2;i++){
        string decrypted_msg=decrypt(transposition_key,ciphertexts_vec[i]);
        string final_decrypted=remove_padding(decrypted_msg);
        cout<< final_decrypted<< " "<< calc_hash(final_decrypted)<< " "<< endl;
        if(calc_hash(final_decrypted)!=calc_hash(plaintexts_vec[i])) return false;

    }
    return true;
}
vector<int> brute_force(vector<string> ciphertexts_vec,vector<string> plaintexts_vec){
    vector<int> discover_key={1,2,3,4,5,6,7,8,9};
     for(int i=1;i<10;i++){

        if(ciphertexts_vec[0].size()%i!=0) continue;
        vector<int> key_elements(discover_key.begin(),discover_key.begin()+i);
        vector<vector<int>> key_set=permute(key_elements);
        // print_keyset(key_set);
     
        for(auto transposition_key: key_set){
            string decrypted_msg=decrypt(transposition_key,ciphertexts_vec[0]);
            string final_decrypted=remove_padding(decrypted_msg);
            
            if(calc_hash(final_decrypted)!=calc_hash(plaintexts_vec[0])) continue;
            else {
                
                if(check_all_ciphertexts(transposition_key,ciphertexts_vec,plaintexts_vec)==true);
                    return transposition_key;
            }

        }
    }
    cout<< " KEY NOT FOUND"<< endl;
    return {-1};
}
int main()
{
    vector<int> key = {3, 1, 4, 2, 5, 6, 7};
    // string plaintext = "helloworld";

    vector<string> plaintexts_vec;
    for(int i=0;i<2;i++){
        string plaintext;
        cin>> plaintext;
        plaintexts_vec.push_back(plaintext);
    }
    for(auto plaintext : plaintexts_vec)
    cout << "Plaintext: " << plaintext <<" " <<calc_hash(plaintext)<< endl;

    // int hash_value=calc_hash(plaintext);
    vector<string> ciphertexts_vec;
    vector<string> decrypted_vec;
    for(auto plaintext: plaintexts_vec){
        ciphertexts_vec.push_back(encrypt(key,plaintext));
    }   
    for(auto ciphertext: ciphertexts_vec){
        cout << "ciphertext: " << ciphertext<< endl;
    }
    for(auto ciphertext: ciphertexts_vec){
        decrypted_vec.push_back(decrypt(key, ciphertext));
    }
    


    vector<int> discovered_key=brute_force(ciphertexts_vec,plaintexts_vec);
    cout<< endl;
    for(auto it : discovered_key){
        cout<< it<< " ";
    }


    return 0;
}
