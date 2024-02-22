
from tables import get_s_box_value, get_inv_s_box_value, get_r_con_value

def bytes2matrix(key):
    matrix = []
    for i in range(0, len(key), 4):
        temp_row = []
        for j in range(4):
            temp_row.append(key[i + j])
        matrix.append(temp_row)
    return matrix

def matrix2bytes(matrix):
    byte_list = []
    for row in matrix:
        for byte in row:
            byte_list.append(byte)
    return bytes(byte_list)

def rot_word_left(word):
    return word[1:]+word[0]

def transpose(input_list):
    transposed_list = []

    for i in range(4):
        for j in range(4):
            original_index = i
            original_index <<= 2  
            original_index += j  
            value = (input_list[original_index] >> (24 - 8 * i)) & 0xFF
            value <<= (8 * i)
            transposed_list.append(value)

    input_list[:] = transposed_list

def xtime(a):
    if (a & 0x80):
        result = ((a << 1) ^ 0x1B) & 0xFF
    else:
        result = (a << 1)
    return result

def xor_bytes(a, b):
    length=len(a)
    x=[]
    for i in range(length):
        x.append(a[i]^b[i])
    return bytes(x)

def keyExpansion(key):
    key = bytes2matrix(key)
    Nr = 10
    Nk = 4
    i = 0

    while len(key) < 4 * (Nr + 1):
        word = list(key[-1])
        if i % 4 == 0:
            word.append(word.pop(0))
            for index in range(len(word)):
                word[index] = get_s_box_value(word[index] // 0x10, word[index] % 0x10)
            word[0] ^= get_r_con_value(i)
            i += 1
        word = xor_bytes(word, key[-4])
        key.append(list(word))

    return key

def addRoundKey(state, key):
    Nk = 4
    new_state = []
    for i in range(Nk):
        temp_row = []
        for j in range(Nk):
            temp_row.append(state[i][j] ^ key[i][j])
        new_state.append(temp_row)
    return new_state

def sub_bytes(s):
    new_state = []
    for i in range(4):
        temp_row = []
        for j in range(4):
            temp_row.append(get_s_box_value(s[i][j] // 0x10, s[i][j] % 0x10))
        new_state.append(temp_row)
    return new_state

def inv_sub_bytes(s):
    new_state = []
    for i in range(4):
        temp_row = []
        for j in range(4):
            temp_row.append(get_inv_s_box_value(s[i][j] // 0x10, s[i][j] % 0x10))
        new_state.append(temp_row)
    return new_state

def shift_rows(state):
    state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
    state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]
    return state

def inv_shift_rows(state):
    state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
    state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
    return state

def mix_columns(state):
    new_state = []
    for i in range(4):
        new_column = []
        for j in range(4):
            temp_xor = state[i][j % 4] ^ state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ^ xtime(state[i][j % 4] ^ state[i][(j + 1) % 4])
            new_column.append(temp_xor)
        new_state.append(new_column)
    return new_state

    
def inv_mix_columns(state):
    for i in range(4):
        x = xtime(state[i][0] ^ state[i][2])
        y = xtime(state[i][1] ^ state[i][3])
        state[i][0] ^= xtime(x)
        state[i][1] ^= xtime(y)
        state[i][2] ^= xtime(x)
        state[i][3] ^= xtime(y)

    state=mix_columns(state)
    return state

def encrypt(plaintext, key):
  
    state=bytes2matrix(plaintext)
    expanded_key=keyExpansion(key)
    
    state=addRoundKey(state,expanded_key[0:4])
    print(f"Initial_state : {matrix2bytes(state).hex()}")
    round_states = {}
    print()
    for round in range(1,10):
        state=sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state=addRoundKey(state,expanded_key[4*round:4*(round+1)])
        new_state=state
        round_states[round]=new_state
       
        print(f"{round}th state : {matrix2bytes(new_state).hex()}")
        
    state = sub_bytes(state)
    state = shift_rows(state)
    state = addRoundKey(state, expanded_key[10*4:11*4])
    print()
    return state,round_states
        

def decrypt(ciphertext, key):
  
    print("Starting Decryption ...")

    state = ciphertext
    expanded_key = keyExpansion(key)
    print(f"Decryption starting state : {matrix2bytes(state).hex()}")
    print()
    state = addRoundKey(state,expanded_key[10*4:11*4])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    round_states = {}

    for round in range(9, 0, -1):
        print(f"{10-round}th state : {matrix2bytes(state).hex()}")
        state = addRoundKey(state, expanded_key[round*4:(round+1)*4])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        round_states[round] = state
    print()
    print(f"Final state : {matrix2bytes(state).hex()}")
    state = addRoundKey(state, expanded_key[0:4])
    return state,round_states

def solve(pt):
  print("\n-----------------------------------------------------\n")
  print("Input :",pt)
  plaintext=pt.encode("utf-8")
  key="ABCDabcd12344321".encode("utf-8")
  print(f"The intial Plaintext taken : {plaintext}")
  print(f"The key used for AES : {key}")
  print()

  ciphertext,round_states_enc=encrypt(plaintext,key)
  print(f"Ciphertext : {matrix2bytes(ciphertext).hex()}")

  print("\n-----------------------------------------------------\n")

  plaintext,round_states_dec=decrypt(ciphertext,key)
  Original_plaintext=matrix2bytes(plaintext).decode("utf-8")
  print("\n-----------------------------------------------------\n")
  print(f"Original Plaintext : {Original_plaintext}")
  print("\n-----------------------------------------------------\n")

if __name__ == '__main__':
   solve("Two One Nine Two")
   solve("Ones Twos Threes")
   solve("Four Five Eleven")
   while True:
        s = input("Enter plaintext : ")
        if(len(s)!=16):
            print("INVALID INPUT! Plaintext length should be 16 bytes or 128 bits")
        else:
            solve(s)
            break
