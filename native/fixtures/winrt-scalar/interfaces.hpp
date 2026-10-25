#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <inspectable.h>
#include <activation.h>

inline constexpr wchar_t WVB_RUNTIME_CLASS[] = L"Wvb.Test.WvbScalarRuntimeClass";
inline constexpr IID IID_IWvbScalarFactory =
    {0x5f1c7a3e, 0x2b4d, 0x4e6f, {0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x51}};
inline constexpr IID IID_IWvbScalarInstance =
    {0x5f1c7a3e, 0x2b4d, 0x4e6f, {0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x52}};

struct IWvbScalarInstance : IInspectable {
  virtual HRESULT STDMETHODCALLTYPE Reserved0() = 0;
  virtual HRESULT STDMETHODCALLTYPE Reserved1() = 0;
  virtual HRESULT STDMETHODCALLTYPE Transform(UINT32, UINT32 *) = 0;
};

struct IWvbScalarFactory : IInspectable {
  virtual HRESULT STDMETHODCALLTYPE ReservedFactory() = 0;
  virtual HRESULT STDMETHODCALLTYPE Create(IWvbScalarInstance **) = 0;
};
