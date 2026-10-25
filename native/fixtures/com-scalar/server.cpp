#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Owned test server; neither a Windows service nor an Xbox implementation.
static const CLSID CLSID_WvbScalarObject =
    {0xba9a4da2, 0x79fe, 0x4b31, {0x8d, 0xb4, 0x20, 0x1a, 0xf0, 0x26, 0x6c, 0x11}};
static const IID IID_IWvbScalarObject =
    {0xba9a4da2, 0x79fe, 0x4b31, {0x8d, 0xb4, 0x20, 0x1a, 0xf0, 0x26, 0x6c, 0x12}};

struct IWvbScalarObject : IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Transform(UINT32 input, UINT32 *output) = 0;
};

static HANDLE finished;
static LONG objects;
static FILE *logfile;

static void record(const char *event) {
  if (logfile) {
    fprintf(logfile, "{\"event\":\"%s\",\"pid\":%lu,\"thread\":%lu}\n",
            event, GetCurrentProcessId(), GetCurrentThreadId());
    fflush(logfile);
  }
}

class Scalar final : public IWvbScalarObject {
  LONG references = 1;
public:
  Scalar() { InterlockedIncrement(&objects); record("activated"); }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (iid != IID_IUnknown && iid != IID_IWvbScalarObject) return E_NOINTERFACE;
    *out = static_cast<IWvbScalarObject *>(this);
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references); }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG left = InterlockedDecrement(&references);
    if (!left) {
      record("released");
      delete this;
      if (!InterlockedDecrement(&objects)) SetEvent(finished);
    }
    return left;
  }
  HRESULT STDMETHODCALLTYPE Transform(UINT32 input, UINT32 *output) override {
    record("invoke");
    if (!output) return E_POINTER;
    if (input == UINT32_MAX) return E_INVALIDARG;
    *output = input + 1;
    return S_OK;
  }
};

class Factory final : public IClassFactory {
  LONG references = 1;
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
    *out = static_cast<IClassFactory *>(this);
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references); }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG left = InterlockedDecrement(&references);
    if (!left) delete this;
    return left;
  }
  HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *outer, REFIID iid, void **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (outer) return CLASS_E_NOAGGREGATION;
    Scalar *object = new Scalar();
    HRESULT hr = object->QueryInterface(iid, out);
    object->Release();
    return hr;
  }
  HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return E_NOTIMPL; }
};

static int oracle() {
  IWvbScalarObject *object = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_WvbScalarObject, nullptr, CLSCTX_LOCAL_SERVER,
                               IID_IWvbScalarObject, reinterpret_cast<void **>(&object));
  if (FAILED(hr) || !object) {
    fprintf(stderr, "oracle: activation HRESULT=0x%08lx\n", static_cast<unsigned long>(hr));
    return 2;
  }
  UINT32 output = 0xa5a5a5a5;
  hr = object->Transform(41, &output);
  printf("{\"event\":\"oracle\",\"input\":41,\"hresult\":%ld,\"output\":%u,\"caller_pid\":%lu}\n",
         static_cast<long>(hr), output, GetCurrentProcessId());
  bool success = hr == S_OK && output == 42;
  output = 0xa5a5a5a5;
  hr = object->Transform(UINT32_MAX, &output);
  printf("{\"event\":\"oracle-error\",\"hresult\":%ld,\"output\":%u}\n",
         static_cast<long>(hr), output);
  success = success && hr == E_INVALIDARG && output == 0;
  object->Release();
  return success ? 0 : 2;
}

int main(int argc, char **argv) {
  bool oracle_mode = argc == 2 && !strcmp(argv[1], "--oracle");
  bool server_mode = (argc == 3 || (argc == 4 &&
      (!_stricmp(argv[3], "-Embedding") || !_stricmp(argv[3], "/Embedding")))) &&
      !strcmp(argv[1], "--server") && argv[2][0];
  if (!oracle_mode && !server_mode) {
    fputs("usage: com_scalar.exe --oracle | --server LOG_FILE [-Embedding]\n", stderr);
    return 2;
  }
  if (server_mode) {
    logfile = fopen(argv[2], "a");
    if (!logfile) { perror("server: startup log"); return 2; }
    record("starting");
  }
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(hr)) {
    fprintf(stderr, "COM initialization HRESULT=0x%08lx\n", static_cast<unsigned long>(hr));
    record("initialization-failed");
    if (logfile) fclose(logfile);
    return 2;
  }
  int result = 2;
  if (oracle_mode) {
    result = oracle();
  } else {
    finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (finished) {
      Factory *factory = new Factory();
      DWORD cookie = 0;
      hr = CoRegisterClassObject(CLSID_WvbScalarObject, factory, CLSCTX_LOCAL_SERVER,
                                REGCLS_MULTIPLEUSE, &cookie);
      factory->Release();
      if (SUCCEEDED(hr)) {
        record("ready");
        DWORD wait = WaitForSingleObject(finished, 120000);
        CoRevokeClassObject(cookie);
        result = wait == WAIT_OBJECT_0 ? 0 : 2;
        record(result ? "expired" : "completed");
      } else {
        record("registration-failed");
        fprintf(stderr, "server: registration HRESULT=0x%08lx\n", static_cast<unsigned long>(hr));
      }
    } else {
      record("event-failed");
      fprintf(stderr, "server: event creation error=%lu\n", GetLastError());
    }
  }
  CoUninitialize();
  if (finished) CloseHandle(finished);
  if (logfile) fclose(logfile);
  return result;
}
