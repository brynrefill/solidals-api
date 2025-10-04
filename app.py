"""
API name: Solidals
Author: brynrefill
Description: ...
Contact: info@brynrefill.com
"""

from flask import Flask, jsonify, request
import hashlib
import math
import requests
import secrets
import string

app = Flask(__name__)

# server endpoints
@app.route('/', methods=['GET'])
def doc():
    """API documentation endpoint"""
    return jsonify({
        "name": "Solidals API",
        "endpoints": {
            " GET /": "API documentation"
            # TODO: add Swagger documentation
        }
    })

@app.route('/gen-password', methods=['GET'])
def gen_password():
    try:
        length = 16 # default length
        length_arg = request.args.get('l')

        if length_arg:
            length = int(length_arg)

        if length < 12 or length > 128:
            raise ValueError

        # set of available chars
        alphabet = string.ascii_letters + string.digits + string.punctuation

        # ensure password includes at least one of each type in alphabet
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(string.punctuation)
        ]

        password += [secrets.choice(alphabet) for _ in range(length - 4)]

        # shuffle to avoid a predictable pattern
        secrets.SystemRandom().shuffle(password)

        password = ''.join(password)

        # password entropy estimation (in bits):
        # entropy_bits = log2(chars_range ^ length) = length * log2(chars_range)
        # max number of combinations/passwords to try to guess a password = 2 ^ (entropy_bits)

        chars_range = len(string.ascii_letters) + len(string.digits) + len(string.punctuation)
        entropy_bits = round(length * math.log2(chars_range), 2)

        return jsonify({
            "password": password,
            "entropy": entropy_bits
            # TODO: add time to crack the password
        })

    # to handle also the case where the user send something different than a number
    except ValueError as e:
        return jsonify({"error": "Password length must be between 12 and 128 characters!"}), 400

@app.route('/check-breach', methods=['POST'])
def check_breach():
    """Check breach endpoint"""
    password = request.form.get('p') # reading data assuming that the POST data is sent as
                                     # form data (application/x-www-form-urlencoded or multipart/form-data)
    if not password:
        return jsonify({"error": f"Parameter 'p' is required!"}), 400 # bad request status code

    # hash password with SHA1 algorithm
    hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # take first 5 hash chars for k-anonymity
    prefix = hash[:5]
    suffix = hash[5:]

    # query HIBP API:
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    # debug prints
    # print(f"pw: {password}")
    # print(f"hash: {hash}")
    # print(f"prefix: {prefix}")
    # print(f"suffix: {suffix}")
    # print(f"url: {url}")
    # print(f"res:\n{res.text}")

    '''
    e.g.:
        pw: hello
        hash: AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D
        prefix: AAF4C
        suffix: 61DDCC5E8A2DABEDE0F3B482CD9AEA9434D
        url: https://api.pwnedpasswords.com/range/AAF4C
        res:
        000AB2DEE342D579F6FE914C85B9CF98EDE:5
        003EC0930A89382B60E0C012A0F916AC33F:1
        0049BCEC3D5BBE2BE6E330D672F10B61802:13
        0059D41E74575F8580A0687D1791E9B313F:126
        009CBD6FF7932CE73BED1A40961EB70634A:1
        ...
        61DDCC5E8A2DABEDE0F3B482CD9AEA9434D:403640
        ...
        FFC724CBED25A326BBE370D466CF5797737:12
        FFCD66AAB0F73B33D17DEAF787DCFDAFD5F:1
        FFD7087991CE11EC76B58AB18EC0EA7F568:169
    '''

    if res.status_code != 200:
        return jsonify({"error": "Error querying HIBP API!"}), 500 # internal server error status code

    suffixes = res.text.splitlines()
    found = False # if the password appears in the dataset
    count = 0     # how many times the password appears in the dataset

    # check if suffix is in the list of suffixes in response
    for line in suffixes:
        line = line.split(':')
        if line[0] == suffix:
            found = True
            count = int(line[1])
            break

    return jsonify({
        "breached": found,
        "count": count
    })

# server errors handling
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found!"}), 404

# TODO: add all the necessary server errors handles

def main():
    print("x------------------------------------------------------------------------+")
    print("| Starting Solidals API...                                               |")
    print("| Example usage:                                                         |")
    print("|    curl -X  GET http://localhost:5000/                                 |")
    print("|    curl -X  GET http://localhost:5000/gen-password?l=42                |")
    print("|    curl -X POST http://localhost:5000/check-breach -d \"p=hello\"        |")
    print("o------------------------------------------------------------------------/")

if __name__ == '__main__':
    main()
    app.run(debug=True, host='0.0.0.0', port=5000)
