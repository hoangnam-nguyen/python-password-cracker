import hashlib

top_pw_list = open('./top-10000-passwords.txt').read().split()
known_salts = open('./known-salts.txt').read().split()

def crack_sha1_hash(hash, use_salts = False):
  password_list = []
  hashed_pw_list = []
  
  if use_salts == False:
    password_list = top_pw_list.copy()

    for password in password_list:
      hashed_pw_list.append(hashlib.sha1(password.encode('utf-8')).hexdigest())

    for i, hashed_pw in enumerate(hashed_pw_list):
      if hashed_pw == hash:
        return password_list[i]
    return "PASSWORD NOT IN DATABASE"

  else:
    for top_pw in top_pw_list:
      for salt in known_salts:
        password_list.append(salt + top_pw)       # Even index
        password_list.append(top_pw + salt)       # Odd index

    for password in password_list:
      hashed_pw_list.append(hashlib.sha1(password.encode('utf-8')).hexdigest())

    for i, hashed_pw in enumerate(hashed_pw_list):
      if (hashed_pw == hash) and (i % 2 == 0):
        return password_list[i][10:]
      elif (hashed_pw == hash) and (i % 2 == 1):
        return password_list[i][:-10]
    return "PASSWORD NOT IN DATABASE"
