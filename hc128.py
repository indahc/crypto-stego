P = [None] * 512
Q = [None] * 512
i = 0

def hex_to_bytes(str):
  """Converts a hex string to a byte string"""
  
  return str.zfill(8).decode("hex")

def bytes_to_hex(bytes):
  """Converts a byte string to a hex string"""

  return bytes.encode("hex")

def hex_to_int(str):
  """Converts hex string to int"""

  return int(str, 16)

def int_to_hex(n):
  """Converts an integer to hex string"""

  return "%x" % n

def get_byte(x, n):
  """Get the n'th byte of integer x
  n = 0 : Least significant byte
  """
  
  for i in range(0, n):
    x = x / 256
  return x % 256

def get_4byte(x, n):
  """Get the n'th 4byte of integer x
  n = 0 : Least significant 4byte
  """
  
  for i in range(0, n):
    x = x / 4294967296
  return x % 4294967296

def int32(n):
  """Return the 32 least significant bits of the number n"""

  return n % 4294967296

def mod512(n):
  return n % 512

def rotl(x,n):
  x = int32(x << n) ^ int32(x >> (32 - n))
  return x

def f1(x):
  return rotl(x, 25) ^ rotl(x, 14) ^ (x >> 3)

def f2(x):
  return rotl(x, 15) ^ rotl(x, 13) ^ (x >> 10)

def g1(x, y, z):
  return int32((rotl(x, 22) ^ rotl(z, 9)) + rotl(y, 24))

def g2(x, y, z):
  return int32((rotl(x, 10) ^ rotl(z, 23)) + rotl(y, 8))

def h1(x):
  return int32(Q[get_byte(x, 0)] + Q[256 + get_byte(x, 2)])

def h2(x):
  return int32(P[get_byte(x, 0)] + P[256 + get_byte(x, 2)])

def init(K, IV):
  """Initializing the key and IV into P and Q"""

  global P
  global Q

  # Converting hex key string to int
  K = hex_to_int(bytes_to_hex(hex_to_bytes(K)[::-1]))
  IV = hex_to_int(bytes_to_hex(hex_to_bytes(IV)[::-1]))

  # Initializing W
  W = [None] * 1280

  for i in range(0,8):
    W[i] = get_4byte(K, i % 4)

  for i in range(8,16):
    W[i] = get_4byte(IV, i % 4)

  for i in range(16,1280):
    W[i] = int32(f2(W[i-2]) + W[i-7] + f1(W[i-15]) + W[i-16] + i)

  # Initializing P and Q
  for i in range(0,512):
    P[i] = W[i+256]
    Q[i] = W[i+768]   

  # Running the cipher 1024 times and replacing table elements
  for i in range(0,512):
    P[i] = int32(P[i] + g1(P[mod512(i-3)], P[mod512(i-10)], P[mod512(i-511)]) ^ h1(P[mod512(i-12)]))
  for i in range(0,512):
    Q[i] = int32(Q[i] + g2(Q[mod512(i-3)], Q[mod512(i-10)], Q[mod512(i-511)]) ^ h2(Q[mod512(i-12)]))

def keygen():
  """Generates and returns a 32 bit key"""
  
  global P
  global Q
  global i

  j = mod512(i)
  key = None
  
  if (i % 1024) < 512:
    P[j] = int32(P[j] + g1(P[mod512(j-3)], P[mod512(j-10)], P[mod512(j-511)]))
    key = h1(P[mod512(j-12)]) ^ P[j]
  else:
    Q[j] = int32(Q[j] + g2(Q[mod512(j-3)], Q[mod512(j-10)], Q[mod512(j-511)]))
    key = h2(Q[mod512(j-12)]) ^ Q[j]
  
  i = i + 1
  return bytes_to_hex(hex_to_bytes(int_to_hex(key))[::-1])