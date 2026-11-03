// IpswArcHandler.cpp — read-only 7-Zip Formats handler for .ipswarc

#include "StdAfx.h"

#include "Common/ComTry.h"
#include "Common/MyString.h"
#include "Common/StringConvert.h"

#include "Windows/PropVariant.h"
#include "Windows/TimeUtils.h"

#include "7zip/Common/ProgressUtils.h"
#include "7zip/Common/RegisterArc.h"
#include "7zip/Common/StreamUtils.h"

#include "ipswarc_lib.h"
#include "arcfmt.h"

using namespace NWindows;

namespace NArchive {
namespace NIpswArc {

static const Byte kProps[] =
{
  kpidPath,
  kpidSize,
  kpidMTime,
};

Z7_CLASS_IMP_CHandler_IInArchive_0
  CMyComPtr<IInStream> _stream;
  ipswarc_archive_t *_arc;
  UInt64 _phySize;
  bool _isArc;

  static int StreamSeek(void *ctx, uint64_t absOff)
  {
    IInStream *s = (IInStream *)ctx;
    return (InStream_SeekSet(s, absOff) == S_OK) ? 0 : -1;
  }
  static int StreamReadExact(void *ctx, void *buf, size_t len)
  {
    IInStream *s = (IInStream *)ctx;
    Byte *p = (Byte *)buf;
    while (len)
    {
      const UInt32 chunk = (len > 0x80000000u) ? 0x80000000u : (UInt32)len;
      UInt32 got = 0;
      if (s->Read(p, chunk, &got) != S_OK || got == 0)
        return -1;
      p += got;
      len -= got;
    }
    return 0;
  }

public:
  CHandler(): _arc(NULL), _phySize(0), _isArc(false) {}
  ~CHandler() { Close(); }
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps_NO_Table

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = _arc ? ipswarc_num_items(_arc) : 0;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidExtension: prop = "ipswarc"; break;
    case kpidPhySize: if (_isArc) prop = _phySize; break;
    case kpidErrorFlags:
    {
      UInt32 v = 0;
      if (!_isArc) v |= kpv_ErrorFlags_IsNotArc;
      prop = v;
      break;
    }
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  NCOM::CPropVariant prop;
  if (!_arc)
    return E_FAIL;
  const char *name = NULL;
  UInt64 size = 0;
  UInt16 modTime = 0, modDate = 0;
  if (ipswarc_item_info(_arc, index, &name, &size, &modTime, &modDate) != 0)
    return E_INVALIDARG;
  switch (propID)
  {
    case kpidPath:
      if (name)
        prop = MultiByteToUnicodeString(name, CP_ACP);
      break;
    case kpidSize:
    case kpidPackSize:
      prop = size;
      break;
    case kpidMTime:
    {
      const UInt32 dos = ((UInt32)modDate << 16) | (UInt32)modTime;
      if (dos != 0)
        PropVariant_SetFrom_DosTime(prop, dos);
      break;
    }
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

static const unsigned kSignatureSize = IPSWARC_WRAP_MAGIC_LEN;
static const Byte kSignature[kSignatureSize] = {
  '4','s','t','a','l','4','e','v','r'
};

API_FUNC_static_IsArc IsArc_IpswArc(const Byte *p, size_t size)
{
  if (size < kSignatureSize)
    return k_IsArc_Res_NEED_MORE;
  if (memcmp(p, kSignature, kSignatureSize) != 0)
    return k_IsArc_Res_NO;
  return k_IsArc_Res_YES;
}
}

Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 * /* maxCheckStartPosition */,
    IArchiveOpenCallback * /* openArchiveCallback */))
{
  COM_TRY_BEGIN
  Close();
  if (!stream)
    return S_FALSE;

  RINOK(InStream_SeekToBegin(stream))

  Byte sig[kSignatureSize];
  UInt32 processed = 0;
  RINOK(stream->Read(sig, kSignatureSize, &processed))
  if (processed != kSignatureSize || memcmp(sig, kSignature, kSignatureSize) != 0)
    return S_FALSE;

  _stream = stream;

  ipswarc_reader_t reader;
  reader.seek = StreamSeek;
  reader.read = StreamReadExact;
  reader.ctx = (void *)(IInStream *)_stream;

  ipswarc_archive_t *arc = NULL;
  if (ipswarc_open_reader(&reader, &arc) != 0)
  {
    _stream.Release();
    return S_FALSE;
  }

  UInt64 phy = 0;
  if (InStream_GetSize_SeekToEnd(stream, phy) == S_OK)
    _phySize = phy;
  else
    _phySize = 0;

  _arc = arc;
  _isArc = true;
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Close())
{
  if (_arc)
  {
    ipswarc_close(_arc);
    _arc = NULL;
  }
  _stream.Release();
  _phySize = 0;
  _isArc = false;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testMode, IArchiveExtractCallback *extractCallback))
{
  COM_TRY_BEGIN
  if (!_arc)
    return E_FAIL;

  const bool allFilesMode = (numItems == (UInt32)(Int32)-1);
  if (allFilesMode)
    numItems = ipswarc_num_items(_arc);
  if (numItems == 0)
    return S_OK;

  UInt64 totalSize = 0;
  for (UInt32 i = 0; i < numItems; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    UInt64 sz = 0;
    if (ipswarc_item_info(_arc, index, NULL, &sz, NULL, NULL) == 0)
      totalSize += sz;
  }
  RINOK(extractCallback->SetTotal(totalSize))

  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
  lps->Init(extractCallback, false);

  UInt64 currentTotal = 0;
  for (UInt32 i = 0; i < numItems; i++)
  {
    lps->InSize = currentTotal;
    lps->OutSize = currentTotal;
    RINOK(lps->SetCur())

    const UInt32 index = allFilesMode ? i : indices[i];
    UInt64 itemSize = 0;
    ipswarc_item_info(_arc, index, NULL, &itemSize, NULL, NULL);

    CMyComPtr<ISequentialOutStream> outStream;
    const Int32 askMode = testMode ?
        NExtract::NAskMode::kTest :
        NExtract::NAskMode::kExtract;
    RINOK(extractCallback->GetStream(index, &outStream, askMode))
    if (!testMode && !outStream)
    {
      currentTotal += itemSize;
      continue;
    }
    RINOK(extractCallback->PrepareOperation(askMode))

    Int32 opRes = NExtract::NOperationResult::kDataError;
    uint8_t *data = NULL;
    size_t len = 0;
    if (ipswarc_extract_mem(_arc, index, &data, &len) == 0)
    {
      if (testMode || !outStream)
        opRes = NExtract::NOperationResult::kOK;
      else
      {
        const HRESULT wr = WriteStream(outStream, data, len);
        opRes = (wr == S_OK) ? NExtract::NOperationResult::kOK
                             : NExtract::NOperationResult::kDataError;
      }
      free(data);
    }
    outStream.Release();
    RINOK(extractCallback->SetOperationResult(opRes))
    currentTotal += itemSize;
  }
  return S_OK;
  COM_TRY_END
}

REGISTER_ARC_I(
  "IpswArc", "ipswarc", NULL, 0xC8,
  kSignature,
  0,
  NArcInfoFlags::kPureStartOpen,
  IsArc_IpswArc)

}}
