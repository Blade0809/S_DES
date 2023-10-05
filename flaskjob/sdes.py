"""S-DES"""
import time
import threading

s_box_0 = [[1, 0, 3, 2],
       [3, 2, 1, 0],
       [0, 2, 1, 3],
       [3, 1, 0, 2]]

s_box_1 = [[0, 1, 2, 3],
       [2, 3, 1, 0],
       [3, 0, 1, 2],
       [2, 1, 0, 3]]

p_10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
p_8 = (6, 3, 7, 4, 8, 5, 10, 9)
left_shift_1 = (2, 3, 4, 5, 1)
left_shift_2 = (3, 4, 5, 1, 2)
ip_table = (2, 6, 3, 1, 4, 8, 5, 7)
ip_inverse_table = (4, 1, 3, 5, 7, 2, 8, 6)
ep_box = (4, 1, 2, 3, 2, 3, 4, 1)
sp_box = (2, 4, 3, 1)


def permute(input, order_table):
    output = ""
    for i in order_table:
        output += input[i - 1]
    return output


def left_shift(K, left_shift):
    left_half = K[:5]
    right_half = K[5:]
    shifted_left = permute(left_half, left_shift)
    shifted_right = permute(right_half, left_shift)
    return shifted_left + shifted_right
#
#
# def get_key(K, p_10, p_8):
#     p_10_key = permute(K, p_10)
#     k_1 = permute(left_shift(p_10_key, left_shift_1, left_shift_2), p_8)  # get k1
#     k_2 = permute(left_shift(left_shift(p_10_key, left_shift_1, left_shift_2), left_shift_1, left_shift_2), p_8)
#     # get k2
#     return k_1, k_2


def f_function(right_half, k):
    expand = permute(right_half, ep_box)  # 8 expand to 10
    xor = '{0:08b}'.format(int(expand, 2) ^ int(k, 2))  # xor
    s0_input = xor[:4]
    s1_input = xor[4:]  # separate to 2 parts
    s0_row = int(s0_input[0] + s0_input[-1], 2)
    s0_col = int(s0_input[1:-1], 2)
    s1_row = int(s1_input[0] + s1_input[-1], 2)
    s1_col = int(s1_input[1:-1], 2)
    s0_output = '{0:02b}'.format(s_box_0[s0_row][s0_col])
    s1_output = '{0:02b}'.format(s_box_1[s1_row][s1_col])
    s_output = s0_output + s1_output
    return permute(s_output, sp_box)


def encrypt(plain, K):
    if len(plain) != 8 or len(K) != 10:
        return
    p_10_key = permute(K, p_10)
    k_1 = permute(left_shift(p_10_key, left_shift_1), p_8)  # get k1
    k_2 = permute(left_shift(left_shift(p_10_key, left_shift_1), left_shift_2), p_8)
    plain = permute(plain, ip_table)
    left_0 = plain[:4]
    right_0 = plain[4:]
    # first round
    left_1 = right_0
    f_result = f_function(right_0, k_1)
    right_1 = '{0:04b}'.format(int(left_0, 2) ^ int(f_result, 2))
    # second round
    f_result = f_function(right_1, k_2)
    right_2 = '{0:04b}'.format(int(left_1, 2) ^ int(f_result, 2))
    return permute(right_2 + right_1, ip_inverse_table)


def decrypt(cyper, K):
    if len(cyper) != 8 or len(K) != 10:
        return
    p_10_key = permute(K, p_10)
    k_1 = permute(left_shift(p_10_key, left_shift_1), p_8)  # get k1
    k_2 = permute(left_shift(left_shift(p_10_key, left_shift_1), left_shift_2), p_8)
    cyper = permute(cyper, ip_table)
    right_2 = cyper[:4]
    left_2 = cyper[4:]
    # first round
    f_result = f_function(left_2, k_2)
    left_1 = '{0:04b}'.format(int(right_2, 2) ^ int(f_result, 2))
    # second round
    f_result = f_function(left_1, k_1)
    right_1 = '{0:04b}'.format(int(left_2, 2) ^ int(f_result, 2))
    return permute(right_1 + left_1, ip_inverse_table)


def is_length(str):
    if len(str) < 8:
        delta = 8 - len(str)
        for i in range(delta):
            str = '0' + str
    return str


def ascii_encrypt(plain_ascii, K):
    global binary_plain
    list_ascii = list(plain_ascii)
    plain = ""
    for character in list_ascii:
        flag = ord(character)
        binary_plain = '0' + bin(flag)[2:]
        plain += binary_plain
    # print(plain)
    cipher = ""
    len_plain = len(plain)
    for i in range(int(len_plain / 8)):
        part_cipher = encrypt(plain[8*i:8*i+8], K)
        decimal_cipher = int(part_cipher, 2)
        cipher += chr(decimal_cipher)
    return cipher


def ascii_decrypt(cipher_ascii, K):
    global binary_cipher
    list_ascii = list(cipher_ascii)
    plain = ""
    for character in list_ascii:
        flag = ord(character)
        binary_cipher = is_length(bin(flag)[2:])
        part_plain = decrypt(binary_cipher, K)
        decimal_plain = int(part_plain, 2)
        plain += chr(decimal_plain)
    return plain


def get_unique(lst):
    unique = []
    for element in lst:
        if int(element) not in unique:
            unique.append(element)
    return unique


def crack(data):
    start = time.perf_counter()
    results = []
    for key in range(1024):
        success = True
        for pair in data:
            plaintext = pair['plaintext']
            ciphertext = pair['ciphertext']
            result = decrypt(ciphertext, format(key, '010b'))
            if result != plaintext:
                success = False
                break
        if success:
            results.append(format(key, '010b'))
    results = get_unique(results)
    delta = time.perf_counter() - start
    return results, delta


def brute_force_single(pair, keys, results):
    plaintext = pair['plaintext']
    ciphertext = pair['ciphertext']
    for key in keys:
        result = decrypt(ciphertext, format(key, '010b'))
        if result == plaintext:
            results.append(format(key, '010b'))
            break


def brute_force(data):
    start = time.perf_counter()
    results = []
    keys = range(1024)
    threads = []

    for pair in data:
        thread = threading.Thread(target=brute_force_single, args=(pair, keys, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    delta = time.perf_counter() - start
    return results, delta
