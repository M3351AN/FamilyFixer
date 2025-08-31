#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// 用GCC的话就不用加这个宏，但是MSVC和Clang都得加，顺从了
#include <Windows.h>

#include "ScryptVerify.h"

static constexpr int kMaxPIN = 9999;
static constexpr int kThreadCount = 4;  // 写死4线程，也够用了

static inline uint8_t HexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::runtime_error("Invalid hex char");
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
  if (hex.size() % 2 != 0) throw std::runtime_error("Hex length must be even");
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((HexNibble(hex[2 * i]) << 4) |
                                  HexNibble(hex[2 * i + 1]));
  }
  return out;
}

static char* BruteForce(uint8_t* salt, uint32_t salt_size,
                        uint8_t* password_hash, uint32_t hash_size) {
  // 遍历逻辑就在这里
  auto start_time = std::chrono::steady_clock::now();

  std::atomic<bool> found(false);
  std::atomic<int> progress(0);
  char result_str[5] = {0};
  std::vector<std::thread> threads;

  auto worker = [&](int start, int end) {
    char pin_str[5];
    for (int i = start; i <= end && !found.load(); ++i) {
      snprintf(pin_str, sizeof(pin_str), "%04u", i);
      if (VerifyScrypt(pin_str, salt, salt_size, password_hash, hash_size, 8192,
                       8, 1)) {
        found = true;
        strncpy_s(result_str, pin_str, sizeof(result_str));
        printf(" Found: %s\n", pin_str);
        break;
      }
      progress.fetch_add(1, std::memory_order_relaxed);
    }
  };

  int range = (kMaxPIN + 1) / kThreadCount;
  for (int t = 0; t < kThreadCount; ++t) {
    int start = t * range;
    int end = (t == kThreadCount - 1) ? kMaxPIN : (start + range - 1);
    threads.emplace_back(worker, start, end);
  }

  int total = kMaxPIN + 1;
  while (!found && progress < total) {
    printf("\rBrute force progress: %.2f%%", 100.0 * progress.load() / total);
    fflush(stdout);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  for (auto& th : threads) th.join();

  auto end_time = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     end_time - start_time)
                     .count();
  printf("\nTime usage: %.2f s\n", elapsed / 1000.0);

  return found ? _strdup(result_str) : nullptr;
}

// 读取注册表字符串值的轮子
std::string ReadRegistryString(HKEY root, const char* subkey,
                               const char* value) {
  HKEY hKey;
  char buf[512];
  DWORD bufSize = sizeof(buf);
  if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    throw std::runtime_error("RegOpenKeyExA failed");
  if (RegQueryValueExA(hKey, value, nullptr, nullptr, (LPBYTE)buf, &bufSize) !=
      ERROR_SUCCESS) {
    RegCloseKey(hKey);
    throw std::runtime_error("RegQueryValueExA failed");
  }
  RegCloseKey(hKey);
  return std::string(buf, bufSize - 1);  // 去掉字符串结尾的停止符
}

// 读取注册表DWORD值的轮子
DWORD ReadRegistryDWORD(HKEY root, const char* subkey, const char* value) {
  HKEY hKey;
  DWORD data = 0, dataSize = sizeof(data);
  if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    throw std::runtime_error("RegOpenKeyExA failed");
  if (RegQueryValueExA(hKey, value, nullptr, nullptr, (LPBYTE)&data,
                       &dataSize) != ERROR_SUCCESS) {
    RegCloseKey(hKey);
    throw std::runtime_error("RegQueryValueExA failed");
  }
  RegCloseKey(hKey);
  return data;
}

// 解析localconfig.vdf的轮子
std::string ParseParentalSettings(const std::string& vdf_path) {
  std::ifstream fin(vdf_path, std::ios::binary);
  if (!fin) throw std::runtime_error("!! localconfig.vdf does not exist.\n");
  std::stringstream buffer;
  buffer << fin.rdbuf();
  std::string content = buffer.str();

  std::string key = "\"ParentalSettings\"\n\t{\n\t\t\"settings\"\t\t\"";
  // 这里直接找到这一段字符串就好了，不需要完整的vdf解析轮子
  size_t pos = content.find(key);
  if (pos == std::string::npos)
    throw std::runtime_error(
        "ParentalSettings not found, maybe this account did not enable family "
        "view.\n");
  pos += key.size();
  size_t end = content.find("\"", pos);
  if (end == std::string::npos)
    throw std::runtime_error(
        "!! ParentalSettings value end quote not found!\n");
  return content.substr(pos, end - pos);
}

int main(int argc, char* argv[]) {
  std::string vdf_path;
  if (argc > 1) {
    // 拖入vdf文件, 直接跳过拼接路径的步骤
    vdf_path = argv[1];
    printf("Using file %s\n", vdf_path.c_str());
  } else {
    printf("Fetch steam path.\n");
    std::string installPath = ReadRegistryString(
        HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam",
        "InstallPath");
    // 发现在使用一些steambypass的学习版后可能会导致这个注册表值不对
    // 但是只要再启动一次steam客户端就正常了，暂且不理他
    printf("Steam install path: %s\n", installPath.c_str());
    printf("Fetch active user.\n");
    DWORD activeUser = ReadRegistryDWORD(
        HKEY_CURRENT_USER, "Software\\Valve\\Steam\\ActiveProcess",
        "ActiveUser");
    if (activeUser)
      printf("Active user friend code: %d\n", activeUser);
    else {
      printf(
          "No active user found. Please enter your friend code or start up "
          "steam client.\nFriend code: ");
      scanf_s("%u", &activeUser);
      if (!activeUser) throw std::runtime_error("Invalid friend code");
    }
    printf("Fetch localconfig.vdf.\n");
    std::ostringstream oss;
    oss << installPath << "\\userdata\\" << activeUser
        << "\\config\\localconfig.vdf";
    vdf_path = oss.str();
  }

  printf("Parse parental settings.\n");
  std::ifstream test(vdf_path);
  if (!test) {
    printf("localconfig.vdf 文件不存在: %s\n", vdf_path.c_str());
    exit(1);
  }
  std::string parental_settings = ParseParentalSettings(vdf_path);

  std::vector<uint8_t> settings_bytes = HexToBytes(parental_settings);
  printf("Parse protobuf.\n");
  std::vector<uint8_t> salt, target_hash;
  std::string email;
  size_t i = 0;
  // 在这里简单解析protobuf中需要的值
  while (i < settings_bytes.size()) {
    uint8_t key = settings_bytes[i++];
    uint32_t field_number = key >> 3;
    uint32_t wire_type = key & 0x07;
    if (wire_type != 2) {
      while (i < settings_bytes.size() && (settings_bytes[i++] & 0x80));
      continue;
    }
    uint32_t len = 0, shift = 0;
    while (i < settings_bytes.size()) {
      uint8_t b = settings_bytes[i++];
      len |= (b & 0x7F) << shift;
      if (!(b & 0x80)) break;
      shift += 7;
    }
    if (i + len > settings_bytes.size()) break;
    if (field_number == 7) {
      salt.assign(settings_bytes.begin() + i, settings_bytes.begin() + i + len);
    } else if (field_number == 8) {
      target_hash.assign(settings_bytes.begin() + i,
                         settings_bytes.begin() + i + len);
    } else if (field_number == 11) {
      email.assign(settings_bytes.begin() + i,
                   settings_bytes.begin() + i + len);
      printf("Recovery e-mail: %s\n", email.c_str());
    }
    i += len;
  }

  auto pin =
      BruteForce(salt.data(), static_cast<uint32_t>(salt.size()),
                 target_hash.data(), static_cast<uint32_t>(target_hash.size()));
  printf("Family view PIN is: %s\n", pin);
  system("pause");
}
