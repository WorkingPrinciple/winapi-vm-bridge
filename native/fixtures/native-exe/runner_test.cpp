#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

struct Capture {
  std::vector<unsigned char> bytes;
  bool overflow = false;
};

static void read_pipe(HANDLE pipe, Capture *capture, size_t maximum) {
  std::array<unsigned char, 4096> buffer{};
  for (;;) {
    DWORD count = 0;
    if (!ReadFile(pipe, buffer.data(), (DWORD)buffer.size(), &count, NULL) ||
        count == 0) {
      break;
    }
    if (capture->bytes.size() + count > maximum) {
      capture->overflow = true;
      break;
    }
    capture->bytes.insert(capture->bytes.end(), buffer.begin(),
                          buffer.begin() + count);
  }
}

static bool hash_file(const wchar_t *path, unsigned char output[32]) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) return false;
  BCRYPT_ALG_HANDLE algorithm = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  DWORD object_size = 0, copied = 0;
  std::vector<unsigned char> object;
  std::array<unsigned char, 4096> buffer{};
  bool ok = false;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) <
          0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        (PUCHAR)&object_size, sizeof(object_size), &copied, 0) <
          0)
    goto done;
  object.resize(object_size);
  if (BCryptCreateHash(algorithm, &hash, object.data(), (ULONG)object.size(),
                       NULL, 0, 0) < 0)
    goto done;
  for (;;) {
    DWORD count = 0;
    if (!ReadFile(file, buffer.data(), (DWORD)buffer.size(), &count, NULL))
      goto done;
    if (!count) break;
    if (BCryptHashData(hash, buffer.data(), count, 0) < 0) goto done;
  }
  ok = BCryptFinishHash(hash, output, 32, 0) >= 0;
done:
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  CloseHandle(file);
  return ok;
}

static std::wstring quote(const std::wstring &value) {
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (wchar_t character : value) {
    if (character == L'\\') {
      ++slashes;
    } else if (character == L'"') {
      result.append(slashes * 2 + 1, L'\\');
      result.push_back(character);
      slashes = 0;
    } else {
      result.append(slashes, L'\\');
      slashes = 0;
      result.push_back(character);
    }
  }
  result.append(slashes * 2, L'\\');
  result.push_back(L'"');
  return result;
}

struct Result {
  DWORD exit_code = 0;
  bool timed_out = false;
  Capture out;
  Capture err;
};

static Result run(const wchar_t *target, const std::vector<std::wstring> &args,
                  const char *input, DWORD timeout_ms) {
  SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
  HANDLE stdin_read = NULL, stdin_write = NULL;
  HANDLE stdout_read = NULL, stdout_write = NULL;
  HANDLE stderr_read = NULL, stderr_write = NULL;
  CreatePipe(&stdin_read, &stdin_write, &security, 0);
  CreatePipe(&stdout_read, &stdout_write, &security, 0);
  CreatePipe(&stderr_read, &stderr_write, &security, 0);
  SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

  std::wstring command = quote(target);
  for (const auto &argument : args) {
    command.push_back(L' ');
    command += quote(argument);
  }
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(0);
  wchar_t environment[] = L"WVB_MODE=oracle\0\0";
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = stdin_read;
  startup.hStdOutput = stdout_write;
  startup.hStdError = stderr_write;
  PROCESS_INFORMATION process = {};
  Result result;
  if (!CreateProcessW(target, mutable_command.data(), NULL, NULL, TRUE,
                      CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
                          CREATE_NO_WINDOW,
                      environment, NULL, &startup, &process)) {
    result.exit_code = 0xffffffff;
    return result;
  }
  HANDLE job = CreateJobObjectW(NULL, NULL);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                          sizeof(limits));
  AssignProcessToJobObject(job, process.hProcess);
  ResumeThread(process.hThread);
  CloseHandle(process.hThread);
  CloseHandle(stdin_read);
  CloseHandle(stdout_write);
  CloseHandle(stderr_write);
  DWORD written = 0;
  WriteFile(stdin_write, input, (DWORD)strlen(input), &written, NULL);
  CloseHandle(stdin_write);
  std::thread out_thread(read_pipe, stdout_read, &result.out, 4096);
  std::thread err_thread(read_pipe, stderr_read, &result.err, 4096);
  const DWORD wait = WaitForSingleObject(process.hProcess, timeout_ms);
  if (wait == WAIT_TIMEOUT || result.out.overflow || result.err.overflow) {
    result.timed_out = wait == WAIT_TIMEOUT;
    TerminateJobObject(job, 0xdead);
    WaitForSingleObject(process.hProcess, 5000);
  }
  GetExitCodeProcess(process.hProcess, &result.exit_code);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  out_thread.join();
  err_thread.join();
  CloseHandle(stdout_read);
  CloseHandle(stderr_read);
  return result;
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 3 || wcslen(argv[2]) != 64) return 64;
  unsigned char expected[32] = {};
  for (size_t index = 0; index < 32; ++index) {
    wchar_t pair[3] = {argv[2][index * 2], argv[2][index * 2 + 1], 0};
    expected[index] = (unsigned char)wcstoul(pair, NULL, 16);
  }
  unsigned char observed[32] = {};
  if (!hash_file(argv[1], observed) || memcmp(expected, observed, 32)) return 65;
  Result normal = run(argv[1], {L"alpha", L"two words", L"--exit=17"},
                      "fixture-input", 5000);
  std::string out(normal.out.bytes.begin(), normal.out.bytes.end());
  std::string err(normal.err.bytes.begin(), normal.err.bytes.end());
  if (normal.exit_code != 17 || normal.timed_out ||
      out.find("mode=oracle") == std::string::npos ||
      out.find("arg2=two words") == std::string::npos ||
      out.find("stdin=fixture-input") == std::string::npos ||
      err.find("fixture-stderr") == std::string::npos)
    return 70;
  Result timeout = run(argv[1], {L"--sleep-ms=5000"}, "", 200);
  if (!timeout.timed_out) return 71;
  puts("native-exe-job-oracle=ok exit=17 timeout=contained");
  return 0;
}
