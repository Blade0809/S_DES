# S_DES
## Homework Report
### Level 1: basic test
GUI: 

<img width="633" alt="截屏2023-10-04 10 29 30" src="https://github.com/Blade0809/S_DES/assets/125954865/68e77f2b-aa8b-4abc-b55e-d9eca90de648">

1. Input the correct plaintext and key, we can encrypt and get the ciphertext.

<img width="256" alt="截屏2023-10-04 19 18 46" src="https://github.com/Blade0809/S_DES/assets/125954865/670eea21-d004-43c5-a212-e49d13e5f939">

2. Input the correct ciphertext and key, we can decrypt and get the plaintext.

<img width="256" alt="截屏2023-10-04 19 18 46" src="https://github.com/Blade0809/S_DES/assets/125954865/a17ef8d1-2950-4ea9-a331-0895e220fd17">

We can see that the plaintext we get through decrypt is the same as the original one, thus **the encrypt and the decrypt are inverse operations**.

3. If either the key or the plain/cipher is not correspond to the correct length, it will return an error.

<img width="290" alt="截屏2023-10-04 10 58 27" src="https://github.com/Blade0809/S_DES/assets/125954865/9a166fa4-a811-4bd8-b4ff-b2ae7de0fa61">

### Level 2: cross-testing
Answer from other group. It is obvious that we are the same.

![IMG_3948](https://github.com/Blade0809/S_DES/assets/125954865/33d11e0f-9120-4565-8ba3-2568aac31e15)

### Level 3: ASCII
We transfor every ASCII character to a 8-bit binary number, so a word of any length can be encrypted and decrypted.
Here is an example of the word "YAN".

encrypt:

<img width="295" alt="截屏2023-10-04 19 19 53" src="https://github.com/Blade0809/S_DES/assets/125954865/2d548fba-0047-4873-8827-bd00ad218316">

decrypt:

<img width="301" alt="截屏2023-10-04 19 20 35" src="https://github.com/Blade0809/S_DES/assets/125954865/a7da7841-5199-4a22-a7dd-23132e5a6e3f">

### Level 4: crack
It allows us to input one or more plain/cipher to get the satisfied key. Also, it will tell us how long it takes to crack the key.

Single-threading:

For example, we use one pair 10011101/01010111 to crack the key, it turns out that we will get 6 keys. Moreover, the cracking time is 0.0277s.

https://github.com/Blade0809/S_DES/assets/125954865/ed517759-dc07-4f03-bbc9-545d38ee1adf

Muti-threading:

For muti-threading, the cracking time is 0.0223s. Compared with single-threading one, the speed is a little faster.

https://github.com/Blade0809/S_DES/assets/125954865/bca180a1-05ea-4a57-a3e2-c0b97ef60d5f

If we input more than one pair of plain/cipher, we can get less keys. For example

<img width="733" alt="截屏2023-10-05 09 55 28" src="https://github.com/Blade0809/S_DES/assets/125954865/4deb08f0-ded9-48f2-9359-2a3d6cd2657e">

### Level 5: closed test

Through testing, we found that if we input **one pair plain/cipher, we are likely to get 6 keys**. But if we input **two or more pairs, we can get two keys**, just as that in level 4. But there is a question, **no matter how many keys we input, we can not get one unique key**. So we try to find out the reason.

According to level 4's results, we find that for instance key 1001011100 and 1000010100 can both encrypt plain 10011101 to cipher 01010111.

We find that different keys generate different subkeys. To find out the reason, we analysis the process through the output of every step. Finally we find that the problem comes **in the process of S_BOX**. The key 1001011100 and 1000010100 are different in the **4th and 7th bit**, but in s_box they both produce 1010 and 1100, thus producing the same ciphertext. Moreover, this condition **can only happen when the 4th and 7th are different in the same time**.

<img width="201" alt="截屏2023-10-05 16 24 06" src="https://github.com/Blade0809/S_DES/assets/125954865/4b70ebd1-cb2b-4f77-8ca9-c06d4759d771">

## Development Manual
### Algorithm
S-DES is a classic block cipher algorithm used to encrypt and decrypt 8bits of plaintext data. It mainly consists of two stages: key generation and data encryption/decryption.

1. Key generation:
- The user provides a 10bits key
- The key generates two 8bit sub-keys: k_1 and k_2

2. Data encryption:
- The plaintext is divided into two 4-bit blocks: L_0 and R_0
- Perform initial permutation (IP) operations on L_0 and R_0.
- Iterative operations: including extension, XOR, S-box substitution, p-box substitution, and XOR operations.
- Swap the left and right halves and iterate again
- The final left half block (L_4) and right half block (R_4) are merged and subjected to inverse initial permutations (IP^-1) to produce an 8-bit ciphertext.

3. Data decryption:
- Similar to the data encryption process, but with subkeys K2 (in reverse order) and K1

### Modules
#### Get the key
```python
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

p_10_key = permute(K, p_10)
k_1 = permute(left_shift(p_10_key, left_shift_1), p_8)  # get k1
k_2 = permute(left_shift(left_shift(p_10_key, left_shift_1), left_shift_2), p_8)
```

In this module, we realize two functions. Permute() changes the order of the text, left_shift() realizes the leftshift step.

First, we permute original key with p_10, then we do leftshift twice to get k_1 and k_2.

#### F-function
```python
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
```

We use permute and xor to realize the f-function.

#### Encrypt
```python
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
```

Honestly speaking, this module is just follow the given order without any new functions. 

#### Decrypt
```python
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
```

Similiar to Encrypt().

#### ASCII
```python
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
```

In this module, we encrypt ASCII to ASCII. We first turn every character to a 8-bit binary number. In this step, we need a function is_length() to make sure any short number be extended to 8-bit long.

Then, in function ascii_encrypt(), we encrypt every character one by one and get the cipher.

#### Crack(Single-thread)
```python
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
```

First, **we use time.perf_counter() to record and calculate the time**. Then, we use a loop to exhaust every key to find all the keys which satisfy the pair.

#### Crack(Muti-thread)
```python
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
```

Similiar to the single-thread, the difference is we use threading to add more threads, it will crack quickly.

### GUI
We can see different input fields and buttons. According to their names we can understand what they can do. Once we click the button, it will giveback the answer or the error.

### Announcements

- The S-DES algorithm has a relatively small key space and is not a highly secure encryption algorithm, which is not suitable for processing highly sensitive data. Understand its limitations and take necessary safety measures.
- The secure storage and distribution of keys is a key issue when using S-DES. Ensure that the key is not disclosed to unauthorized persons.
















