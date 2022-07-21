import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again.')
    return response

# figuring out the number of times the password was leaked
def get_pw_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def check_pwned_api(password):
    #check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    stored_response = request_api_data(first5_char)
    return get_pw_leaks_count(stored_response, tail)

def main():
    with open('password.txt', 'r') as file:
        pw_list = file.readlines()
    for password in pw_list:
        pw = password[:-1]
        count = check_pwned_api(pw)
        if count:
            print(f'{pw} was found {count} times...you should probably change your password.')
        else:
            print(f'{pw} was NOT found. You should continue using the password :)')
    return 'DONE!'


if __name__ == '__main__':
    sys.exit(main()) 
    #sys.exit to make sure the script ends