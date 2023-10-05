from flask import Flask, request, render_template
from sdes import encrypt, decrypt, ascii_encrypt, ascii_decrypt, crack, get_unique

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    plaintext = request.form['plaintext']  # get the plaintext
    key = request.form['key']
    ciphertext = encrypt(plaintext, key)
    if ciphertext:
        return render_template('index.html', ciphertext=ciphertext)
    else:
        return render_template('index.html', ciphertext='Error! Check the length!')


@app.route('/decrypt', methods=['POST'])
def decrypt_text():
    ciphertext = request.form['ciphertext']
    key = request.form['key']
    plaintext = decrypt(ciphertext, key)
    if plaintext:
        return render_template('index.html', plaintext=plaintext)
    else:
        return render_template('index.html', plaintext='Error! Check the length!')


@app.route('/ascii_encrypt', methods=['POST'])
def ascii_plaintext():
    asciiplaintext = request.form['ascii_plaintext']
    key = request.form['key']
    cipher_ascii_plaintext = ascii_encrypt(asciiplaintext, key)
    return render_template('index.html', cipher_ascii_plaintext=cipher_ascii_plaintext)


@app.route('/ascii_decrypt', methods=['POST'])
def ascii_ciphertext():
    asciiciphertext = request.form['ascii_ciphertext']
    key = request.form['key']
    plain_ascii_ciphertext = ascii_decrypt(asciiciphertext, key)
    return render_template('index.html', plain_ascii_ciphertext=plain_ascii_ciphertext)


@app.route('/crack', methods=['POST'])
def bruteforce():
    data = []
    for i in range(len(request.form.getlist('plaintext[]'))):
        data.append({
            'plaintext': request.form.getlist('plaintext[]')[i],
            'ciphertext': request.form.getlist('ciphertext[]')[i]
        })
    keys, time = crack(data)
    keys = get_unique(keys)
    if keys:
        return render_template('index.html', bruteforce_result=f"successfully cracked. keys are: {', '.join(keys)}",
                               time=f"it takes {time}s")
    else:
        return render_template('index.html', bruteforce_result="failed", time="error")


@app.route('/bruteforce', methods=['POST'])
def bruteforce2():
    data = []
    for i in range(len(request.form.getlist('plaintext[]'))):
        data.append({
            'plaintext': request.form.getlist('plaintext[]')[i],
            'ciphertext': request.form.getlist('ciphertext[]')[i]
        })
    keys, time = crack(data)
    keys = get_unique(keys)
    if keys:
        return render_template('index.html', bruteforce_result=f"successfully cracked. keys are: {', '.join(keys)}",
                               time=f"it takes {time}s")
    else:
        return render_template('index.html', bruteforce_result="failed", time="error")


if __name__ == '__main__':
    app.run(debug=True)

# test example: key 1001011100 plaintext: 10011101 ciphertext: 10101101
# test example: key 1001011100 plaintext: 10100110 ciphertext: 10111110
# test example: key 1001011100 plaintext: 10110100 ciphertext: 10010000
# test example: key 1001011100 plaintext: 10011001 ciphertext: 00101000      1000010100  1001011100
# test example2: key 1001011100 plaintext: YAN ciphertext: Z:*

