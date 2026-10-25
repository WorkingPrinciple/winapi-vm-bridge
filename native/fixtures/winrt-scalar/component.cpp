#include <initguid.h>
#include "interfaces.hpp"
#include <objbase.h>
#include <winstring.h>
#include <stdint.h>
#include <stdio.h>
#include <new>

static LONG objects;
static SRWLOCK log_lock = SRWLOCK_INIT;

static bool record(const char *event) {
  wchar_t path[32768];
  DWORD length = GetEnvironmentVariableW(L"WVB_WINRT_FIXTURE_LOG", path, 32768);
  if (!length || length >= 32768) {
    fputs("winrt-fixture: WVB_WINRT_FIXTURE_LOG missing/oversized\n", stderr);
    return false;
  }
  AcquireSRWLockExclusive(&log_lock);
  FILE *file = _wfopen(path, L"ab");
  bool ok = false;
  if (file) {
    ok = fprintf(file, "{\"event\":\"%s\",\"pid\":%lu,\"thread\":%lu}\n",
                 event, GetCurrentProcessId(), GetCurrentThreadId()) > 0;
    ok = fclose(file) == 0 && ok;
  }
  ReleaseSRWLockExclusive(&log_lock);
  if (!ok) fputs("winrt-fixture: append log failed\n", stderr);
  return ok;
}

static HRESULT ids(ULONG *count, IID **values, bool factory) {
  if (!count || !values) return E_POINTER;
  *count = 0;
  *values = static_cast<IID *>(CoTaskMemAlloc(sizeof(IID) * (factory ? 2 : 1)));
  if (!*values) return E_OUTOFMEMORY;
  (*values)[0] = factory ? IID_IWvbScalarFactory : IID_IWvbScalarInstance;
  if (factory) (*values)[1] = IID_IActivationFactory;
  *count = factory ? 2 : 1;
  return S_OK;
}

static HRESULT class_name(HSTRING *name) {
  if (!name) return E_POINTER;
  *name = nullptr;
  return WindowsCreateString(WVB_RUNTIME_CLASS, ARRAYSIZE(WVB_RUNTIME_CLASS) - 1, name);
}

class Instance final : public IWvbScalarInstance {
  LONG references = 1;
public:
  Instance() { InterlockedIncrement(&objects); record("instance-created"); }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (iid != IID_IUnknown && iid != IID_IInspectable && iid != IID_IWvbScalarInstance)
      return E_NOINTERFACE;
    *out = static_cast<IWvbScalarInstance *>(this);
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references); }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG left = InterlockedDecrement(&references);
    if (!left) { record("instance-released"); InterlockedDecrement(&objects); delete this; }
    return left;
  }
  HRESULT STDMETHODCALLTYPE GetIids(ULONG *count, IID **values) override {
    return ids(count, values, false);
  }
  HRESULT STDMETHODCALLTYPE GetRuntimeClassName(HSTRING *name) override { return class_name(name); }
  HRESULT STDMETHODCALLTYPE GetTrustLevel(TrustLevel *level) override {
    if (!level) return E_POINTER;
    *level = BaseTrust; return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Reserved0() override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE Reserved1() override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE Transform(UINT32 input, UINT32 *output) override {
    if (!record("invoke")) return E_FAIL;
    if (!output) return E_POINTER;
    if (input == UINT32_MAX) return E_INVALIDARG;
    *output = input + 1;
    return S_OK;
  }
};

class Factory final : public IWvbScalarFactory, public IActivationFactory {
  LONG references = 1;
public:
  Factory() { InterlockedIncrement(&objects); record("factory-created"); }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (iid == IID_IUnknown || iid == IID_IInspectable || iid == IID_IWvbScalarFactory)
      *out = static_cast<IWvbScalarFactory *>(this);
    else if (iid == IID_IActivationFactory)
      *out = static_cast<IActivationFactory *>(this);
    else return E_NOINTERFACE;
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references); }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG left = InterlockedDecrement(&references);
    if (!left) { record("factory-released"); InterlockedDecrement(&objects); delete this; }
    return left;
  }
  HRESULT STDMETHODCALLTYPE GetIids(ULONG *count, IID **values) override {
    return ids(count, values, true);
  }
  HRESULT STDMETHODCALLTYPE GetRuntimeClassName(HSTRING *name) override { return class_name(name); }
  HRESULT STDMETHODCALLTYPE GetTrustLevel(TrustLevel *level) override {
    if (!level) return E_POINTER;
    *level = BaseTrust; return S_OK;
  }
  HRESULT STDMETHODCALLTYPE ActivateInstance(IInspectable **) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE ReservedFactory() override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE Create(IWvbScalarInstance **out) override {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (!record("create")) return E_FAIL;
    *out = new (std::nothrow) Instance();
    return *out ? S_OK : E_OUTOFMEMORY;
  }
};

extern "C" __declspec(dllexport) HRESULT WINAPI
DllGetActivationFactory(HSTRING name, IActivationFactory **out) {
  if (!out) return E_POINTER;
  *out = nullptr;
  UINT32 length = 0;
  const wchar_t *value = WindowsGetStringRawBuffer(name, &length);
  if (length != ARRAYSIZE(WVB_RUNTIME_CLASS) - 1 ||
      memcmp(value, WVB_RUNTIME_CLASS, length * sizeof(wchar_t)))
    return CLASS_E_CLASSNOTAVAILABLE;
  if (!record("factory-request")) return E_FAIL;
  Factory *factory = new (std::nothrow) Factory();
  if (!factory) return E_OUTOFMEMORY;
  *out = static_cast<IActivationFactory *>(factory);
  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT WINAPI DllCanUnloadNow() {
  return InterlockedCompareExchange(&objects, 0, 0) == 0 ? S_OK : S_FALSE;
}
