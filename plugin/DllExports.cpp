// Minimal Formats-DLL exports for ipswarc.dll

#include "StdAfx.h"

#include "Common/MyWindows.h"
#include "Common/MyInitGuid.h"
#include "Common/ComTry.h"

#include "Windows/NtCheck.h"
#include "Windows/PropVariant.h"

#include "7zip/ICoder.h"
#include "7zip/Archive/IArchive.h"
#include "7zip/IDecl.h"

#include "7zVersion.h"

Z7_DEFINE_GUID(CLSID_CArchiveHandler,
    k_7zip_GUID_Data1,
    k_7zip_GUID_Data2,
    k_7zip_GUID_Data3_Common,
    0x10, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00);

#ifdef _WIN32
#if defined(_UNICODE) && !defined(_WIN64) && !defined(UNDER_CE)
#define NT_CHECK_FAIL_ACTION return FALSE;
#endif

static HINSTANCE g_hInstance;

extern "C"
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID /*lpReserved*/)
{
  if (dwReason == DLL_PROCESS_ATTACH)
  {
    g_hInstance = hInstance;
    NT_CHECK
  }
  return TRUE;
}
#endif

extern bool g_CaseSensitive;

STDAPI CreateArchiver(const GUID *clsid, const GUID *iid, void **outObject);

STDAPI CreateObject(const GUID *clsid, const GUID *iid, void **outObject);
STDAPI CreateObject(const GUID *clsid, const GUID *iid, void **outObject)
{
  *outObject = NULL;
  return CreateArchiver(clsid, iid, outObject);
}

STDAPI SetLargePageMode();
STDAPI SetLargePageMode()
{
  return S_OK;
}

STDAPI SetCaseSensitive(Int32 caseSensitive);
STDAPI SetCaseSensitive(Int32 caseSensitive)
{
  g_CaseSensitive = (caseSensitive != 0);
  return S_OK;
}

STDAPI SetCodecs(ICompressCodecsInfo *);
STDAPI SetCodecs(ICompressCodecsInfo *)
{
  return S_OK;
}

STDAPI GetNumberOfMethods(UInt32 *numCodecs);
STDAPI GetNumberOfMethods(UInt32 *numCodecs)
{
  *numCodecs = 0;
  return S_OK;
}

STDAPI GetMethodProperty(UInt32, PROPID, PROPVARIANT *value);
STDAPI GetMethodProperty(UInt32, PROPID, PROPVARIANT *value)
{
  NWindows::NCOM::PropVariant_Clear(value);
  return E_INVALIDARG;
}

STDAPI CreateDecoder(UInt32, const GUID *, void **outObject);
STDAPI CreateDecoder(UInt32, const GUID *, void **outObject)
{
  *outObject = NULL;
  return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI CreateEncoder(UInt32, const GUID *, void **outObject);
STDAPI CreateEncoder(UInt32, const GUID *, void **outObject)
{
  *outObject = NULL;
  return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI GetHashers(IHashers **hashers);
STDAPI GetHashers(IHashers **hashers)
{
  *hashers = NULL;
  return S_OK;
}

STDAPI GetModuleProp(PROPID propID, PROPVARIANT *value);
STDAPI GetModuleProp(PROPID propID, PROPVARIANT *value)
{
  NWindows::NCOM::PropVariant_Clear(value);
  switch (propID)
  {
    case NModulePropID::kInterfaceType:
      NWindows::NCOM::PropVarEm_Set_UInt32(value,
          NModuleInterfaceType::k_IUnknown_VirtDestructor_ThisModule);
      break;
    case NModulePropID::kVersion:
      NWindows::NCOM::PropVarEm_Set_UInt32(value, (MY_VER_MAJOR << 16) | MY_VER_MINOR);
      break;
  }
  return S_OK;
}
