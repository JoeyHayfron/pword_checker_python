import requests
import hashlib
import sys

def request_api_data(partial_hash):
    url = 'https://api.pwnedpasswords.com/range/' + partial_hash
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Request failed with status code {response.status_code}')
    return response

def get_passwords_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, c in hashes:
       if h == hash_to_check:
           return c
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    partial_hash, tail_hash = sha1password[:5], sha1password[5:]
    response = request_api_data(partial_hash)
    return get_passwords_leaks_count(response, tail_hash)


def main(args):
    for pword in args:
        count = pwned_api_check(pword)
        if count:
            print(f"{pword} was found {count} times. You should probably change your password.")
        else:
            print(f"{pword} was not found. You are good to go!!")
    return "done!!"

if __name__ == '__main__':
    main(sys.argv[1:])