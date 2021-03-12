import hashlib
import requests


API_BASE_URI    = "https://api.pwnedpasswords.com/"
# Hard code the padding options to improve secrecy in the request
ADD_PADDING     = "True"    


def is_pwned(query_type: str = None, value: str = None):

    sha1_hash = ""

    # If password is supplied, encode it first, otherwise assume SHA1
    if query_type == "password":
        sha1_hash = hashlib.sha1(value.encode('utf-8')).hexdigest().upper()
    elif query_type == "sha1_hash":
        sha1_hash = value.upper()
    else:
        raise AttributeError("Unexpected query type: %s" % query_type)

    suffix_list = suffix_search(hash_prefix = sha1_hash[0:5])

    # Since the full SHA-1 hash was provided, check to see if it was in the hash suffixes matched in HIBP.
    for suffix in suffix_list:
        if sha1_hash[5:] in suffix:
            # Exact match, so return the actual matching hash with count as a dict
            match, count = suffix.split(':')
            return { 'match': match , 'count': count}

    # Return None if busted.
    return None


def suffix_search(hash_prefix: str = None):

    # Check first if the prefix is even valid before proceeding
    if not hash_prefix or not isinstance(hash_prefix, str):
        raise AttributeError('hash_prefix must be a supplied, and be a string.')

    request_uri = API_BASE_URI + 'range/' + hash_prefix

    headers = {
        'Add-Padding': ADD_PADDING
    }

    r = requests.get(url=request_uri, headers=headers)
    if r.status_code != 200:
        raise RuntimeError('Error code from {0}: {1}'.format(API_BASE_URI, r.status_code))

    # Return all the possible matches as a list
    return r.text.split()


def handleRequest(request):

    if request['method'] == 'POST':
        resp = is_pwned(
            request['body']['type'],
            request['body']['value'] 
        )
        return __new__(
            Response(
            resp, {
            'headers' : { 
                'content-type' : 'application/json',
                'status'       : 200
            }
        }))

    else:
        return __new__(
            Response(
            'Query error.', {
            'headers' : { 
                'content-type' : 'application/json',
                'status'       : 400
            }
        }))

addEventListener('fetch', ( 
    lambda event: event.respondWith( handleRequest(event.request) ) )
)

## For local debugging.
#####
# if __name__ == '__main__':
#     import sys
#     import json
#     t, v = sys.argv[1], sys.argv[2]
#     request = {  
#         'method': 'POST',
#         'body': {
#             'type': t,
#             'value': v,
#         }
#     }
#     handleRequest( request )