#include <cstdint>
#include <cstring>
#include <limits>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

static bool ConstTimeEqual(const std::vector<uint8_t>& a,
                           const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return false;
  uint8_t acc = 0;
  for (size_t i = 0; i < a.size(); ++i) acc |= (a[i] ^ b[i]);
  return acc == 0;
}

struct Sha256Ctx {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buffer[64];
  size_t buflen;
};

static inline uint32_t Rotr(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint32_t BigSigma0(uint32_t x) {
  return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
}
static inline uint32_t BigSigma1(uint32_t x) {
  return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
}
static inline uint32_t SmallSigma0(uint32_t x) {
  return Rotr(x, 7) ^ Rotr(x, 18) ^ (x >> 3);
}
static inline uint32_t SmallSigma1(uint32_t x) {
  return Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10);
}

static constexpr uint32_t kK256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void Sha256Init(Sha256Ctx& ctx) {
  ctx.state[0] = 0x6a09e667;
  ctx.state[1] = 0xbb67ae85;
  ctx.state[2] = 0x3c6ef372;
  ctx.state[3] = 0xa54ff53a;
  ctx.state[4] = 0x510e527f;
  ctx.state[5] = 0x9b05688c;
  ctx.state[6] = 0x1f83d9ab;
  ctx.state[7] = 0x5be0cd19;
  ctx.bitlen = 0;
  ctx.buflen = 0;
  std::memset(ctx.buffer, 0, 64);
}

static void Sha256Transform(Sha256Ctx& ctx, const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (uint32_t(block[4 * i]) << 24) | (uint32_t(block[4 * i + 1]) << 16) |
           (uint32_t(block[4 * i + 2]) << 8) | (uint32_t(block[4 * i + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
  }
  uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3],
           e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t t1 = h + BigSigma1(e) + Ch(e, f, g) + kK256[i] + w[i];
    uint32_t t2 = BigSigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx.state[0] += a;
  ctx.state[1] += b;
  ctx.state[2] += c;
  ctx.state[3] += d;
  ctx.state[4] += e;
  ctx.state[5] += f;
  ctx.state[6] += g;
  ctx.state[7] += h;
}

static void Sha256Update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
  while (len > 0) {
    size_t to_copy = std::min(len, 64 - ctx.buflen);
    std::memcpy(ctx.buffer + ctx.buflen, data, to_copy);
    ctx.buflen += to_copy;
    data += to_copy;
    len -= to_copy;
    if (ctx.buflen == 64) {
      Sha256Transform(ctx, ctx.buffer);
      ctx.bitlen += 512;
      ctx.buflen = 0;
    }
  }
}

static void Sha256Final(Sha256Ctx& ctx, uint8_t out[32]) {
  ctx.bitlen += ctx.buflen * 8;
  ctx.buffer[ctx.buflen++] = 0x80;
  if (ctx.buflen > 56) {
    while (ctx.buflen < 64) ctx.buffer[ctx.buflen++] = 0x00;
    Sha256Transform(ctx, ctx.buffer);
    ctx.buflen = 0;
  }
  while (ctx.buflen < 56) ctx.buffer[ctx.buflen++] = 0x00;
  // append big-endian length
  for (int i = 7; i >= 0; --i) {
    ctx.buffer[ctx.buflen++] = uint8_t((ctx.bitlen >> (i * 8)) & 0xFF);
  }
  Sha256Transform(ctx, ctx.buffer);
  for (int i = 0; i < 8; ++i) {
    out[4 * i] = uint8_t((ctx.state[i] >> 24) & 0xFF);
    out[4 * i + 1] = uint8_t((ctx.state[i] >> 16) & 0xFF);
    out[4 * i + 2] = uint8_t((ctx.state[i] >> 8) & 0xFF);
    out[4 * i + 3] = uint8_t((ctx.state[i]) & 0xFF);
  }
}

static void HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data,
                       size_t data_len, uint8_t out[32]) {
  uint8_t k0[64];
  std::memset(k0, 0, 64);
  if (key_len > 64) {
    Sha256Ctx tmp_ctx;
    Sha256Init(tmp_ctx);
    Sha256Update(tmp_ctx, key, key_len);
    Sha256Final(tmp_ctx, k0);
  } else {
    std::memcpy(k0, key, key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; ++i) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }
  // inner
  Sha256Ctx inner_ctx;
  Sha256Init(inner_ctx);
  Sha256Update(inner_ctx, ipad, 64);
  Sha256Update(inner_ctx, data, data_len);
  uint8_t inner_hash[32];
  Sha256Final(inner_ctx, inner_hash);
  // outer
  Sha256Ctx outer_ctx;
  Sha256Init(outer_ctx);
  Sha256Update(outer_ctx, opad, 64);
  Sha256Update(outer_ctx, inner_hash, 32);
  Sha256Final(outer_ctx, out);
}

static void Pbkdf2HmacSha256(const std::string& password,
                             const std::vector<uint8_t>& salt,
                             uint32_t iterations, size_t dk_len,
                             std::vector<uint8_t>& out) {
  out.assign(dk_len, 0);
  uint32_t blocks = (uint32_t)((dk_len + 31) / 32);
  std::vector<uint8_t> u(32), t(32);
  std::vector<uint8_t> salt_counter(salt);
  salt_counter.resize(salt.size() + 4);
  for (uint32_t i = 1; i <= blocks; ++i) {
    salt_counter[salt.size() + 0] = uint8_t((i >> 24) & 0xFF);
    salt_counter[salt.size() + 1] = uint8_t((i >> 16) & 0xFF);
    salt_counter[salt.size() + 2] = uint8_t((i >> 8) & 0xFF);
    salt_counter[salt.size() + 3] = uint8_t((i) & 0xFF);
    HmacSha256(reinterpret_cast<const uint8_t*>(password.data()),
               password.size(), salt_counter.data(), salt_counter.size(),
               u.data());
    std::memcpy(t.data(), u.data(), 32);
    for (uint32_t j = 1; j < iterations; ++j) {
      HmacSha256(reinterpret_cast<const uint8_t*>(password.data()),
                 password.size(), u.data(), 32, u.data());
      for (int k = 0; k < 32; ++k) t[k] ^= u[k];
    }
    size_t off = (i - 1) * 32;
    size_t cp = std::min((size_t)32, dk_len - off);
    std::memcpy(out.data() + off, t.data(), cp);
  }
}

static inline uint32_t Rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

static void Salsa20_8(uint8_t b[64]) {
  uint32_t x[16];
  for (int i = 0; i < 16; ++i) {
    x[i] = (uint32_t)b[4 * i] | ((uint32_t)b[4 * i + 1] << 8) |
           ((uint32_t)b[4 * i + 2] << 16) | ((uint32_t)b[4 * i + 3] << 24);
  }
  uint32_t z[16];
  for (int i = 0; i < 16; ++i) z[i] = x[i];

  for (int r = 0; r < 8; r += 2) {
    // Odd round (column)
    z[4] ^= Rotl32(z[0] + z[12], 7);
    z[8] ^= Rotl32(z[4] + z[0], 9);
    z[12] ^= Rotl32(z[8] + z[4], 13);
    z[0] ^= Rotl32(z[12] + z[8], 18);

    z[9] ^= Rotl32(z[5] + z[1], 7);
    z[13] ^= Rotl32(z[9] + z[5], 9);
    z[1] ^= Rotl32(z[13] + z[9], 13);
    z[5] ^= Rotl32(z[1] + z[13], 18);

    z[14] ^= Rotl32(z[10] + z[6], 7);
    z[2] ^= Rotl32(z[14] + z[10], 9);
    z[6] ^= Rotl32(z[2] + z[14], 13);
    z[10] ^= Rotl32(z[6] + z[2], 18);

    z[3] ^= Rotl32(z[15] + z[11], 7);
    z[7] ^= Rotl32(z[3] + z[15], 9);
    z[11] ^= Rotl32(z[7] + z[3], 13);
    z[15] ^= Rotl32(z[11] + z[7], 18);

    // Even round (row)
    z[1] ^= Rotl32(z[0] + z[3], 7);
    z[2] ^= Rotl32(z[1] + z[0], 9);
    z[3] ^= Rotl32(z[2] + z[1], 13);
    z[0] ^= Rotl32(z[3] + z[2], 18);

    z[6] ^= Rotl32(z[5] + z[4], 7);
    z[7] ^= Rotl32(z[6] + z[5], 9);
    z[4] ^= Rotl32(z[7] + z[6], 13);
    z[5] ^= Rotl32(z[4] + z[7], 18);

    z[11] ^= Rotl32(z[10] + z[9], 7);
    z[8] ^= Rotl32(z[11] + z[10], 9);
    z[9] ^= Rotl32(z[8] + z[11], 13);
    z[10] ^= Rotl32(z[9] + z[8], 18);

    z[12] ^= Rotl32(z[15] + z[14], 7);
    z[13] ^= Rotl32(z[12] + z[15], 9);
    z[14] ^= Rotl32(z[13] + z[12], 13);
    z[15] ^= Rotl32(z[14] + z[13], 18);
  }

  for (int i = 0; i < 16; ++i) {
    uint32_t y = z[i] + x[i];
    b[4 * i] = (uint8_t)(y & 0xFF);
    b[4 * i + 1] = (uint8_t)((y >> 8) & 0xFF);
    b[4 * i + 2] = (uint8_t)((y >> 16) & 0xFF);
    b[4 * i + 3] = (uint8_t)((y >> 24) & 0xFF);
  }
}

static void BlockMix(const uint8_t* in, uint8_t* out, uint32_t r) {
  uint8_t x[64];
  const uint8_t* last = in + (2 * r - 1) * 64;
  std::memcpy(x, last, 64);

  for (uint32_t i = 0; i < 2 * r; ++i) {
    const uint8_t* b_i = in + i * 64;
    for (int k = 0; k < 64; ++k) x[k] ^= b_i[k];
    Salsa20_8(x);
    uint8_t* y_out;
    if ((i & 1) == 0) {
      y_out = out + (i / 2) * 64;  // even
    } else {
      y_out = out + (r + (i - 1) / 2) * 64;  // odd
    }
    std::memcpy(y_out, x, 64);
  }
}

static uint64_t Integerify(const uint8_t* b, uint32_t r) {
  const uint8_t* p = b + (2 * r - 1) * 64;
  uint64_t val = 0;
  for (int i = 7; i >= 0; --i) {
    val = (val << 8) | p[i];
  }
  return val;
}

static void RoMix(uint8_t* x, uint32_t n, uint32_t r,
                  std::vector<uint8_t>& v_buf) {
  const uint32_t b_size = 128 * r;
  if (v_buf.size() != (size_t)n * b_size) v_buf.assign((size_t)n * b_size, 0);
  std::vector<uint8_t> y(b_size);

  // 1) Fill V
  for (uint32_t i = 0; i < n; ++i) {
    std::memcpy(v_buf.data() + (size_t)i * b_size, x, b_size);
    BlockMix(x, y.data(), r);
    std::memcpy(x, y.data(), b_size);
  }
  // 2) Mix
  for (uint32_t i = 0; i < n; ++i) {
    uint64_t j = Integerify(x, r) % n;
    uint8_t* v_j = v_buf.data() + (size_t)j * b_size;
    for (uint32_t k = 0; k < b_size; ++k) x[k] ^= v_j[k];
    BlockMix(x, y.data(), r);
    std::memcpy(x, y.data(), b_size);
  }
}

std::vector<uint8_t> Scrypt(const std::string& password,
                            const std::vector<uint8_t>& salt, uint32_t n,
                            uint32_t r, uint32_t p, size_t out_len) {
  if ((n & (n - 1)) != 0 || n < 2)
    throw std::runtime_error("n must be power of two and >= 2");
  if (r == 0 || p == 0) throw std::runtime_error("r and p must be >= 1");

  const size_t b_size = (size_t)128 * r;
  if (n > std::numeric_limits<size_t>::max() / b_size)
    throw std::runtime_error("Parameter combination causes size overflow");

  std::vector<uint8_t> b;
  Pbkdf2HmacSha256(password, salt, 1, b_size * p, b);

  std::vector<uint8_t> v;  // n * b_size
  for (uint32_t i = 0; i < p; ++i) {
    uint8_t* x_i = b.data() + i * b_size;
    RoMix(x_i, n, r, v);
  }

  std::vector<uint8_t> dk;
  Pbkdf2HmacSha256(password, b, 1, out_len, dk);
  return dk;
}

bool VerifyScrypt(const std::string& password, const uint8_t* salt,
                  size_t salt_len, const uint8_t* target_hash, size_t hash_len,
                  uint32_t n, uint32_t r, uint32_t p) {
  std::vector<uint8_t> salt_vec(salt, salt + salt_len);
  std::vector<uint8_t> dk = Scrypt(password, salt_vec, n, r, p, hash_len);
  return ConstTimeEqual(dk,
                        std::vector<uint8_t>(target_hash, target_hash + hash_len));
}