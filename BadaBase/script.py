import base64

f = open('ciphertext', 'r')
buf = f.read()
decoded = base64.b64decode(buf)
lst_decoded = list(decoded)
for ind, item in enumerate(lst_decoded):
    lst_decoded[ind] = 255 - item
for item in lst_decoded:
    print(chr(item), end='')
