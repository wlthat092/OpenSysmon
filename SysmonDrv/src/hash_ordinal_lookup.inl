static const CHAR *
SysmonLookupImportOrdinalName(_In_z_ const CHAR *DllName, _In_ USHORT Ordinal)
{
  unsigned int ordinal; // edi
  const CHAR *result; // rax

  ordinal = Ordinal;
  if ( _stricmp(DllName, "ws2_32.dll")
    && _stricmp(DllName, "ws2_32")
    && _stricmp(DllName, "wsock32.dll")
    && _stricmp(DllName, "wsock32") )
  {
    if ( !_stricmp(DllName, "oleaut32.dll") || !_stricmp(DllName, "oleaut32") )
    {
      switch ( ordinal )
      {
        case 2u:
          result = "SysAllocString";
          break;
        case 3u:
          result = "SysReAllocString";
          break;
        case 4u:
          result = "SysAllocStringLen";
          break;
        case 5u:
          result = "SysReAllocStringLen";
          break;
        case 6u:
          result = "SysFreeString";
          break;
        case 7u:
          result = "SysStringLen";
          break;
        case 8u:
          result = "VariantInit";
          break;
        case 9u:
          result = "VariantClear";
          break;
        case 0xAu:
          result = "VariantCopy";
          break;
        case 0xBu:
          result = "VariantCopyInd";
          break;
        case 0xCu:
          result = "VariantChangeType";
          break;
        case 0xDu:
          result = "VariantTimeToDosDateTime";
          break;
        case 0xEu:
          result = "DosDateTimeToVariantTime";
          break;
        case 0xFu:
          result = "SafeArrayCreate";
          break;
        case 0x10u:
          result = "SafeArrayDestroy";
          break;
        case 0x11u:
          result = "SafeArrayGetDim";
          break;
        case 0x12u:
          result = "SafeArrayGetElemsize";
          break;
        case 0x13u:
          result = "SafeArrayGetUBound";
          break;
        case 0x14u:
          result = "SafeArrayGetLBound";
          break;
        case 0x15u:
          result = "SafeArrayLock";
          break;
        case 0x16u:
          result = "SafeArrayUnlock";
          break;
        case 0x17u:
          result = "SafeArrayAccessData";
          break;
        case 0x18u:
          result = "SafeArrayUnaccessData";
          break;
        case 0x19u:
          result = "SafeArrayGetElement";
          break;
        case 0x1Au:
          result = "SafeArrayPutElement";
          break;
        case 0x1Bu:
          result = "SafeArrayCopy";
          break;
        case 0x1Cu:
          result = "DispGetParam";
          break;
        case 0x1Du:
          result = "DispGetIDsOfNames";
          break;
        case 0x1Eu:
          result = "DispInvoke";
          break;
        case 0x1Fu:
          result = "CreateDispTypeInfo";
          break;
        case 0x20u:
          result = "CreateStdDispatch";
          break;
        case 0x21u:
          result = "RegisterActiveObject";
          break;
        case 0x22u:
          result = "RevokeActiveObject";
          break;
        case 0x23u:
          result = "GetActiveObject";
          break;
        case 0x24u:
          result = "SafeArrayAllocDescriptor";
          break;
        case 0x25u:
          result = "SafeArrayAllocData";
          break;
        case 0x26u:
          result = "SafeArrayDestroyDescriptor";
          break;
        case 0x27u:
          result = "SafeArrayDestroyData";
          break;
        case 0x28u:
          result = "SafeArrayRedim";
          break;
        case 0x29u:
          result = "SafeArrayAllocDescriptorEx";
          break;
        case 0x2Au:
          result = "SafeArrayCreateEx";
          break;
        case 0x2Bu:
          result = "SafeArrayCreateVectorEx";
          break;
        case 0x2Cu:
          result = "SafeArraySetRecordInfo";
          break;
        case 0x2Du:
          result = "SafeArrayGetRecordInfo";
          break;
        case 0x2Eu:
          result = "VarParseNumFromStr";
          break;
        case 0x2Fu:
          result = "VarNumFromParseNum";
          break;
        case 0x30u:
          result = "VarI2FromUI1";
          break;
        case 0x31u:
          result = "VarI2FromI4";
          break;
        case 0x32u:
          result = "VarI2FromR4";
          break;
        case 0x33u:
          result = "VarI2FromR8";
          break;
        case 0x34u:
          result = "VarI2FromCy";
          break;
        case 0x35u:
          result = "VarI2FromDate";
          break;
        case 0x36u:
          result = "VarI2FromStr";
          break;
        case 0x37u:
          result = "VarI2FromDisp";
          break;
        case 0x38u:
          result = "VarI2FromBool";
          break;
        case 0x39u:
          result = "SafeArraySetIID";
          break;
        case 0x3Au:
          result = "VarI4FromUI1";
          break;
        case 0x3Bu:
          result = "VarI4FromI2";
          break;
        case 0x3Cu:
          result = "VarI4FromR4";
          break;
        case 0x3Du:
          result = "VarI4FromR8";
          break;
        case 0x3Eu:
          result = "VarI4FromCy";
          break;
        case 0x3Fu:
          result = "VarI4FromDate";
          break;
        case 0x40u:
          result = "VarI4FromStr";
          break;
        case 0x41u:
          result = "VarI4FromDisp";
          break;
        case 0x42u:
          result = "VarI4FromBool";
          break;
        case 0x43u:
          result = "SafeArrayGetIID";
          break;
        case 0x44u:
          result = "VarR4FromUI1";
          break;
        case 0x45u:
          result = "VarR4FromI2";
          break;
        case 0x46u:
          result = "VarR4FromI4";
          break;
        case 0x47u:
          result = "VarR4FromR8";
          break;
        case 0x48u:
          result = "VarR4FromCy";
          break;
        case 0x49u:
          result = "VarR4FromDate";
          break;
        case 0x4Au:
          result = "VarR4FromStr";
          break;
        case 0x4Bu:
          result = "VarR4FromDisp";
          break;
        case 0x4Cu:
          result = "VarR4FromBool";
          break;
        case 0x4Du:
          result = "SafeArrayGetVartype";
          break;
        case 0x4Eu:
          result = "VarR8FromUI1";
          break;
        case 0x4Fu:
          result = "VarR8FromI2";
          break;
        case 0x50u:
          result = "VarR8FromI4";
          break;
        case 0x51u:
          result = "VarR8FromR4";
          break;
        case 0x52u:
          result = "VarR8FromCy";
          break;
        case 0x53u:
          result = "VarR8FromDate";
          break;
        case 0x54u:
          result = "VarR8FromStr";
          break;
        case 0x55u:
          result = "VarR8FromDisp";
          break;
        case 0x56u:
          result = "VarR8FromBool";
          break;
        case 0x57u:
          result = "VarFormat";
          break;
        case 0x58u:
          result = "VarDateFromUI1";
          break;
        case 0x59u:
          result = "VarDateFromI2";
          break;
        case 0x5Au:
          result = "VarDateFromI4";
          break;
        case 0x5Bu:
          result = "VarDateFromR4";
          break;
        case 0x5Cu:
          result = "VarDateFromR8";
          break;
        case 0x5Du:
          result = "VarDateFromCy";
          break;
        case 0x5Eu:
          result = "VarDateFromStr";
          break;
        case 0x5Fu:
          result = "VarDateFromDisp";
          break;
        case 0x60u:
          result = "VarDateFromBool";
          break;
        case 0x61u:
          result = "VarFormatDateTime";
          break;
        case 0x62u:
          result = "VarCyFromUI1";
          break;
        case 0x63u:
          result = "VarCyFromI2";
          break;
        case 0x64u:
          result = "VarCyFromI4";
          break;
        case 0x65u:
          result = "VarCyFromR4";
          break;
        case 0x66u:
          result = "VarCyFromR8";
          break;
        case 0x67u:
          result = "VarCyFromDate";
          break;
        case 0x68u:
          result = "VarCyFromStr";
          break;
        case 0x69u:
          result = "VarCyFromDisp";
          break;
        case 0x6Au:
          result = "VarCyFromBool";
          break;
        case 0x6Bu:
          result = "VarFormatNumber";
          break;
        case 0x6Cu:
          result = "VarBstrFromUI1";
          break;
        case 0x6Du:
          result = "VarBstrFromI2";
          break;
        case 0x6Eu:
          result = "VarBstrFromI4";
          break;
        case 0x6Fu:
          result = "VarBstrFromR4";
          break;
        case 0x70u:
          result = "VarBstrFromR8";
          break;
        case 0x71u:
          result = "VarBstrFromCy";
          break;
        case 0x72u:
          result = "VarBstrFromDate";
          break;
        case 0x73u:
          result = "VarBstrFromDisp";
          break;
        case 0x74u:
          result = "VarBstrFromBool";
          break;
        case 0x75u:
          result = "VarFormatPercent";
          break;
        case 0x76u:
          result = "VarBoolFromUI1";
          break;
        case 0x77u:
          result = "VarBoolFromI2";
          break;
        case 0x78u:
          result = "VarBoolFromI4";
          break;
        case 0x79u:
          result = "VarBoolFromR4";
          break;
        case 0x7Au:
          result = "VarBoolFromR8";
          break;
        case 0x7Bu:
          result = "VarBoolFromDate";
          break;
        case 0x7Cu:
          result = "VarBoolFromCy";
          break;
        case 0x7Du:
          result = "VarBoolFromStr";
          break;
        case 0x7Eu:
          result = "VarBoolFromDisp";
          break;
        case 0x7Fu:
          result = "VarFormatCurrency";
          break;
        case 0x80u:
          result = "VarWeekdayName";
          break;
        case 0x81u:
          result = "VarMonthName";
          break;
        case 0x82u:
          result = "VarUI1FromI2";
          break;
        case 0x83u:
          result = "VarUI1FromI4";
          break;
        case 0x84u:
          result = "VarUI1FromR4";
          break;
        case 0x85u:
          result = "VarUI1FromR8";
          break;
        case 0x86u:
          result = "VarUI1FromCy";
          break;
        case 0x87u:
          result = "VarUI1FromDate";
          break;
        case 0x88u:
          result = "VarUI1FromStr";
          break;
        case 0x89u:
          result = "VarUI1FromDisp";
          break;
        case 0x8Au:
          result = "VarUI1FromBool";
          break;
        case 0x8Bu:
          result = "VarFormatFromTokens";
          break;
        case 0x8Cu:
          result = "VarTokenizeFormatString";
          break;
        case 0x8Du:
          result = "VarAdd";
          break;
        case 0x8Eu:
          result = "VarAnd";
          break;
        case 0x8Fu:
          result = "VarDiv";
          break;
        case 0x90u:
          result = "DllCanUnloadNow";
          break;
        case 0x91u:
          result = "DllGetClassObject";
          break;
        case 0x92u:
          result = "DispCallFunc";
          break;
        case 0x93u:
          result = "VariantChangeTypeEx";
          break;
        case 0x94u:
          result = "SafeArrayPtrOfIndex";
          break;
        case 0x95u:
          result = "SysStringByteLen";
          break;
        case 0x96u:
          result = "SysAllocStringByteLen";
          break;
        case 0x97u:
          result = "DllRegisterServer";
          break;
        case 0x98u:
          result = "VarEqv";
          break;
        case 0x99u:
          result = "VarIdiv";
          break;
        case 0x9Au:
          result = "VarImp";
          break;
        case 0x9Bu:
          result = "VarMod";
          break;
        case 0x9Cu:
          result = "VarMul";
          break;
        case 0x9Du:
          result = "VarOr";
          break;
        case 0x9Eu:
          result = "VarPow";
          break;
        case 0x9Fu:
          result = "VarSub";
          break;
        case 0xA0u:
          result = "CreateTypeLib";
          break;
        case 0xA1u:
          result = "LoadTypeLib";
          break;
        case 0xA2u:
          result = "LoadRegTypeLib";
          break;
        case 0xA3u:
          result = "RegisterTypeLib";
          break;
        case 0xA4u:
          result = "QueryPathOfRegTypeLib";
          break;
        case 0xA5u:
          result = "LHashValOfNameSys";
          break;
        case 0xA6u:
          result = "LHashValOfNameSysA";
          break;
        case 0xA7u:
          result = "VarXor";
          break;
        case 0xA8u:
          result = "VarAbs";
          break;
        case 0xA9u:
          result = "VarFix";
          break;
        case 0xAAu:
          result = "OaBuildVersion";
          break;
        case 0xABu:
          result = "ClearCustData";
          break;
        case 0xACu:
          result = "VarInt";
          break;
        case 0xADu:
          result = "VarNeg";
          break;
        case 0xAEu:
          result = "VarNot";
          break;
        case 0xAFu:
          result = "VarRound";
          break;
        case 0xB0u:
          result = "VarCmp";
          break;
        case 0xB1u:
          result = "VarDecAdd";
          break;
        case 0xB2u:
          result = "VarDecDiv";
          break;
        case 0xB3u:
          result = "VarDecMul";
          break;
        case 0xB4u:
          result = "CreateTypeLib2";
          break;
        case 0xB5u:
          result = "VarDecSub";
          break;
        case 0xB6u:
          result = "VarDecAbs";
          break;
        case 0xB7u:
          result = "LoadTypeLibEx";
          break;
        case 0xB8u:
          result = "SystemTimeToVariantTime";
          break;
        case 0xB9u:
          result = "VariantTimeToSystemTime";
          break;
        case 0xBAu:
          result = "UnRegisterTypeLib";
          break;
        case 0xBBu:
          result = "VarDecFix";
          break;
        case 0xBCu:
          result = "VarDecInt";
          break;
        case 0xBDu:
          result = "VarDecNeg";
          break;
        case 0xBEu:
          result = "VarDecFromUI1";
          break;
        case 0xBFu:
          result = "VarDecFromI2";
          break;
        case 0xC0u:
          result = "VarDecFromI4";
          break;
        case 0xC1u:
          result = "VarDecFromR4";
          break;
        case 0xC2u:
          result = "VarDecFromR8";
          break;
        case 0xC3u:
          result = "VarDecFromDate";
          break;
        case 0xC4u:
          result = "VarDecFromCy";
          break;
        case 0xC5u:
          result = "VarDecFromStr";
          break;
        case 0xC6u:
          result = "VarDecFromDisp";
          break;
        case 0xC7u:
          result = "VarDecFromBool";
          break;
        case 0xC8u:
          result = "GetErrorInfo";
          break;
        case 0xC9u:
          result = "SetErrorInfo";
          break;
        case 0xCAu:
          result = "CreateErrorInfo";
          break;
        case 0xCBu:
          result = "VarDecRound";
          break;
        case 0xCCu:
          result = "VarDecCmp";
          break;
        case 0xCDu:
          result = "VarI2FromI1";
          break;
        case 0xCEu:
          result = "VarI2FromUI2";
          break;
        case 0xCFu:
          result = "VarI2FromUI4";
          break;
        case 0xD0u:
          result = "VarI2FromDec";
          break;
        case 0xD1u:
          result = "VarI4FromI1";
          break;
        case 0xD2u:
          result = "VarI4FromUI2";
          break;
        case 0xD3u:
          result = "VarI4FromUI4";
          break;
        case 0xD4u:
          result = "VarI4FromDec";
          break;
        case 0xD5u:
          result = "VarR4FromI1";
          break;
        case 0xD6u:
          result = "VarR4FromUI2";
          break;
        case 0xD7u:
          result = "VarR4FromUI4";
          break;
        case 0xD8u:
          result = "VarR4FromDec";
          break;
        case 0xD9u:
          result = "VarR8FromI1";
          break;
        case 0xDAu:
          result = "VarR8FromUI2";
          break;
        case 0xDBu:
          result = "VarR8FromUI4";
          break;
        case 0xDCu:
          result = "VarR8FromDec";
          break;
        case 0xDDu:
          result = "VarDateFromI1";
          break;
        case 0xDEu:
          result = "VarDateFromUI2";
          break;
        case 0xDFu:
          result = "VarDateFromUI4";
          break;
        case 0xE0u:
          result = "VarDateFromDec";
          break;
        case 0xE1u:
          result = "VarCyFromI1";
          break;
        case 0xE2u:
          result = "VarCyFromUI2";
          break;
        case 0xE3u:
          result = "VarCyFromUI4";
          break;
        case 0xE4u:
          result = "VarCyFromDec";
          break;
        case 0xE5u:
          result = "VarBstrFromI1";
          break;
        case 0xE6u:
          result = "VarBstrFromUI2";
          break;
        case 0xE7u:
          result = "VarBstrFromUI4";
          break;
        case 0xE8u:
          result = "VarBstrFromDec";
          break;
        case 0xE9u:
          result = "VarBoolFromI1";
          break;
        case 0xEAu:
          result = "VarBoolFromUI2";
          break;
        case 0xEBu:
          result = "VarBoolFromUI4";
          break;
        case 0xECu:
          result = "VarBoolFromDec";
          break;
        case 0xEDu:
          result = "VarUI1FromI1";
          break;
        case 0xEEu:
          result = "VarUI1FromUI2";
          break;
        case 0xEFu:
          result = "VarUI1FromUI4";
          break;
        case 0xF0u:
          result = "VarUI1FromDec";
          break;
        case 0xF1u:
          result = "VarDecFromI1";
          break;
        case 0xF2u:
          result = "VarDecFromUI2";
          break;
        case 0xF3u:
          result = "VarDecFromUI4";
          break;
        case 0xF4u:
          result = "VarI1FromUI1";
          break;
        case 0xF5u:
          result = "VarI1FromI2";
          break;
        case 0xF6u:
          result = "VarI1FromI4";
          break;
        case 0xF7u:
          result = "VarI1FromR4";
          break;
        case 0xF8u:
          result = "VarI1FromR8";
          break;
        case 0xF9u:
          result = "VarI1FromDate";
          break;
        case 0xFAu:
          result = "VarI1FromCy";
          break;
        case 0xFBu:
          result = "VarI1FromStr";
          break;
        case 0xFCu:
          result = "VarI1FromDisp";
          break;
        case 0xFDu:
          result = "VarI1FromBool";
          break;
        case 0xFEu:
          result = "VarI1FromUI2";
          break;
        case 0xFFu:
          result = "VarI1FromUI4";
          break;
        case 0x100u:
          result = "VarI1FromDec";
          break;
        case 0x101u:
          result = "VarUI2FromUI1";
          break;
        case 0x102u:
          result = "VarUI2FromI2";
          break;
        case 0x103u:
          result = "VarUI2FromI4";
          break;
        case 0x104u:
          result = "VarUI2FromR4";
          break;
        case 0x105u:
          result = "VarUI2FromR8";
          break;
        case 0x106u:
          result = "VarUI2FromDate";
          break;
        case 0x107u:
          result = "VarUI2FromCy";
          break;
        case 0x108u:
          result = "VarUI2FromStr";
          break;
        case 0x109u:
          result = "VarUI2FromDisp";
          break;
        case 0x10Au:
          result = "VarUI2FromBool";
          break;
        case 0x10Bu:
          result = "VarUI2FromI1";
          break;
        case 0x10Cu:
          result = "VarUI2FromUI4";
          break;
        case 0x10Du:
          result = "VarUI2FromDec";
          break;
        case 0x10Eu:
          result = "VarUI4FromUI1";
          break;
        case 0x10Fu:
          result = "VarUI4FromI2";
          break;
        case 0x110u:
          result = "VarUI4FromI4";
          break;
        case 0x111u:
          result = "VarUI4FromR4";
          break;
        case 0x112u:
          result = "VarUI4FromR8";
          break;
        case 0x113u:
          result = "VarUI4FromDate";
          break;
        case 0x114u:
          result = "VarUI4FromCy";
          break;
        case 0x115u:
          result = "VarUI4FromStr";
          break;
        case 0x116u:
          result = "VarUI4FromDisp";
          break;
        case 0x117u:
          result = "VarUI4FromBool";
          break;
        case 0x118u:
          result = "VarUI4FromI1";
          break;
        case 0x119u:
          result = "VarUI4FromUI2";
          break;
        case 0x11Au:
          result = "VarUI4FromDec";
          break;
        case 0x11Bu:
          result = "BSTR_UserSize";
          break;
        case 0x11Cu:
          result = "BSTR_UserMarshal";
          break;
        case 0x11Du:
          result = "BSTR_UserUnmarshal";
          break;
        case 0x11Eu:
          result = "BSTR_UserFree";
          break;
        case 0x11Fu:
          result = "VARIANT_UserSize";
          break;
        case 0x120u:
          result = "VARIANT_UserMarshal";
          break;
        case 0x121u:
          result = "VARIANT_UserUnmarshal";
          break;
        case 0x122u:
          result = "VARIANT_UserFree";
          break;
        case 0x123u:
          result = "LPSAFEARRAY_UserSize";
          break;
        case 0x124u:
          result = "LPSAFEARRAY_UserMarshal";
          break;
        case 0x125u:
          result = "LPSAFEARRAY_UserUnmarshal";
          break;
        case 0x126u:
          result = "LPSAFEARRAY_UserFree";
          break;
        case 0x127u:
          result = "LPSAFEARRAY_Size";
          break;
        case 0x128u:
          result = "LPSAFEARRAY_Marshal";
          break;
        case 0x129u:
          result = "LPSAFEARRAY_Unmarshal";
          break;
        case 0x12Au:
          result = "VarDecCmpR8";
          break;
        case 0x12Bu:
          result = "VarCyAdd";
          break;
        case 0x12Cu:
          result = "DllUnregisterServer";
          break;
        case 0x12Du:
          result = "OACreateTypeLib2";
          break;
        case 0x12Fu:
          result = "VarCyMul";
          break;
        case 0x130u:
          result = "VarCyMulI4";
          break;
        case 0x131u:
          result = "VarCySub";
          break;
        case 0x132u:
          result = "VarCyAbs";
          break;
        case 0x133u:
          result = "VarCyFix";
          break;
        case 0x134u:
          result = "VarCyInt";
          break;
        case 0x135u:
          result = "VarCyNeg";
          break;
        case 0x136u:
          result = "VarCyRound";
          break;
        case 0x137u:
          result = "VarCyCmp";
          break;
        case 0x138u:
          result = "VarCyCmpR8";
          break;
        case 0x139u:
          result = "VarBstrCat";
          break;
        case 0x13Au:
          result = "VarBstrCmp";
          break;
        case 0x13Bu:
          result = "VarR8Pow";
          break;
        case 0x13Cu:
          result = "VarR4CmpR8";
          break;
        case 0x13Du:
          result = "VarR8Round";
          break;
        case 0x13Eu:
          result = "VarCat";
          break;
        case 0x13Fu:
          result = "VarDateFromUdateEx";
          break;
        case 0x142u:
          result = "GetRecordInfoFromGuids";
          break;
        case 0x143u:
          result = "GetRecordInfoFromTypeInfo";
          break;
        case 0x145u:
          result = "SetVarConversionLocaleSetting";
          break;
        case 0x146u:
          result = "GetVarConversionLocaleSetting";
          break;
        case 0x147u:
          result = "SetOaNoCache";
          break;
        case 0x149u:
          result = "VarCyMulI8";
          break;
        case 0x14Au:
          result = "VarDateFromUdate";
          break;
        case 0x14Bu:
          result = "VarUdateFromDate";
          break;
        case 0x14Cu:
          result = "GetAltMonthNames";
          break;
        case 0x14Du:
          result = "VarI8FromUI1";
          break;
        case 0x14Eu:
          result = "VarI8FromI2";
          break;
        case 0x14Fu:
          result = "VarI8FromR4";
          break;
        case 0x150u:
          result = "VarI8FromR8";
          break;
        case 0x151u:
          result = "VarI8FromCy";
          break;
        case 0x152u:
          result = "VarI8FromDate";
          break;
        case 0x153u:
          result = "VarI8FromStr";
          break;
        case 0x154u:
          result = "VarI8FromDisp";
          break;
        case 0x155u:
          result = "VarI8FromBool";
          break;
        case 0x156u:
          result = "VarI8FromI1";
          break;
        case 0x157u:
          result = "VarI8FromUI2";
          break;
        case 0x158u:
          result = "VarI8FromUI4";
          break;
        case 0x159u:
          result = "VarI8FromDec";
          break;
        case 0x15Au:
          result = "VarI2FromI8";
          break;
        case 0x15Bu:
          result = "VarI2FromUI8";
          break;
        case 0x15Cu:
          result = "VarI4FromI8";
          break;
        case 0x15Du:
          result = "VarI4FromUI8";
          break;
        case 0x168u:
          result = "VarR4FromI8";
          break;
        case 0x169u:
          result = "VarR4FromUI8";
          break;
        case 0x16Au:
          result = "VarR8FromI8";
          break;
        case 0x16Bu:
          result = "VarR8FromUI8";
          break;
        case 0x16Cu:
          result = "VarDateFromI8";
          break;
        case 0x16Du:
          result = "VarDateFromUI8";
          break;
        case 0x16Eu:
          result = "VarCyFromI8";
          break;
        case 0x16Fu:
          result = "VarCyFromUI8";
          break;
        case 0x170u:
          result = "VarBstrFromI8";
          break;
        case 0x171u:
          result = "VarBstrFromUI8";
          break;
        case 0x172u:
          result = "VarBoolFromI8";
          break;
        case 0x173u:
          result = "VarBoolFromUI8";
          break;
        case 0x174u:
          result = "VarUI1FromI8";
          break;
        case 0x175u:
          result = "VarUI1FromUI8";
          break;
        case 0x176u:
          result = "VarDecFromI8";
          break;
        case 0x177u:
          result = "VarDecFromUI8";
          break;
        case 0x178u:
          result = "VarI1FromI8";
          break;
        case 0x179u:
          result = "VarI1FromUI8";
          break;
        case 0x17Au:
          result = "VarUI2FromI8";
          break;
        case 0x17Bu:
          result = "VarUI2FromUI8";
          break;
        case 0x191u:
          result = "OleLoadPictureEx";
          break;
        case 0x192u:
          result = "OleLoadPictureFileEx";
          break;
        case 0x19Bu:
          result = "SafeArrayCreateVector";
          break;
        case 0x19Cu:
          result = "SafeArrayCopyData";
          break;
        case 0x19Du:
          result = "VectorFromBstr";
          break;
        case 0x19Eu:
          result = "BstrFromVector";
          break;
        case 0x19Fu:
          result = "OleIconToCursor";
          break;
        case 0x1A0u:
          result = "OleCreatePropertyFrameIndirect";
          break;
        case 0x1A1u:
          result = "OleCreatePropertyFrame";
          break;
        case 0x1A2u:
          result = "OleLoadPicture";
          break;
        case 0x1A3u:
          result = "OleCreatePictureIndirect";
          break;
        case 0x1A4u:
          result = "OleCreateFontIndirect";
          break;
        case 0x1A5u:
          result = "OleTranslateColor";
          break;
        case 0x1A6u:
          result = "OleLoadPictureFile";
          break;
        case 0x1A7u:
          result = "OleSavePictureFile";
          break;
        case 0x1A8u:
          result = "OleLoadPicturePath";
          break;
        case 0x1A9u:
          result = "VarUI4FromI8";
          break;
        case 0x1AAu:
          result = "VarUI4FromUI8";
          break;
        case 0x1ABu:
          result = "VarI8FromUI8";
          break;
        case 0x1ACu:
          result = "VarUI8FromI8";
          break;
        case 0x1ADu:
          result = "VarUI8FromUI1";
          break;
        case 0x1AEu:
          result = "VarUI8FromI2";
          break;
        case 0x1AFu:
          result = "VarUI8FromR4";
          break;
        case 0x1B0u:
          result = "VarUI8FromR8";
          break;
        case 0x1B1u:
          result = "VarUI8FromCy";
          break;
        case 0x1B2u:
          result = "VarUI8FromDate";
          break;
        case 0x1B3u:
          result = "VarUI8FromStr";
          break;
        case 0x1B4u:
          result = "VarUI8FromDisp";
          break;
        case 0x1B5u:
          result = "VarUI8FromBool";
          break;
        case 0x1B6u:
          result = "VarUI8FromI1";
          break;
        case 0x1B7u:
          result = "VarUI8FromUI2";
          break;
        case 0x1B8u:
          result = "VarUI8FromUI4";
          break;
        case 0x1B9u:
          result = "VarUI8FromDec";
          break;
        case 0x1BAu:
          result = "RegisterTypeLibForUser";
          break;
        case 0x1BBu:
          result = "UnRegisterTypeLibForUser";
          break;
        default:
          return NULL;
      }
      return result;
    }
    return NULL;
  }
  if ( ordinal > 0x1F4 )
    return NULL;
  if ( ordinal == 500 )
    return "WEP";
  switch ( ordinal )
  {
    case 1u:
      result = "accept";
      break;
    case 2u:
      result = "bind";
      break;
    case 3u:
      result = "closesocket";
      break;
    case 4u:
      result = "connect";
      break;
    case 5u:
      result = "getpeername";
      break;
    case 6u:
      result = "getsockname";
      break;
    case 7u:
      result = "getsockopt";
      break;
    case 8u:
      result = "htonl";
      break;
    case 9u:
      result = "htons";
      break;
    case 0xAu:
      result = "ioctlsocket";
      break;
    case 0xBu:
      result = "inet_addr";
      break;
    case 0xCu:
      result = "inet_ntoa";
      break;
    case 0xDu:
      result = "listen";
      break;
    case 0xEu:
      result = "ntohl";
      break;
    case 0xFu:
      result = "ntohs";
      break;
    case 0x10u:
      result = "recv";
      break;
    case 0x11u:
      result = "recvfrom";
      break;
    case 0x12u:
      result = "select";
      break;
    case 0x13u:
      result = "send";
      break;
    case 0x14u:
      result = "sendto";
      break;
    case 0x15u:
      result = "setsockopt";
      break;
    case 0x16u:
      result = "shutdown";
      break;
    case 0x17u:
      result = "socket";
      break;
    case 0x18u:
      result = "GetAddrInfoW";
      break;
    case 0x19u:
      result = "GetNameInfoW";
      break;
    case 0x1Au:
      result = "WSApSetPostRoutine";
      break;
    case 0x1Bu:
      result = "FreeAddrInfoW";
      break;
    case 0x1Cu:
      result = "WPUCompleteOverlappedRequest";
      break;
    case 0x1Du:
      result = "WSAAccept";
      break;
    case 0x1Eu:
      result = "WSAAddressToStringA";
      break;
    case 0x1Fu:
      result = "WSAAddressToStringW";
      break;
    case 0x20u:
      result = "WSACloseEvent";
      break;
    case 0x21u:
      result = "WSAConnect";
      break;
    case 0x22u:
      result = "WSACreateEvent";
      break;
    case 0x23u:
      result = "WSADuplicateSocketA";
      break;
    case 0x24u:
      result = "WSADuplicateSocketW";
      break;
    case 0x25u:
      result = "WSAEnumNameSpaceProvidersA";
      break;
    case 0x26u:
      result = "WSAEnumNameSpaceProvidersW";
      break;
    case 0x27u:
      result = "WSAEnumNetworkEvents";
      break;
    case 0x28u:
      result = "WSAEnumProtocolsA";
      break;
    case 0x29u:
      result = "WSAEnumProtocolsW";
      break;
    case 0x2Au:
      result = "WSAEventSelect";
      break;
    case 0x2Bu:
      result = "WSAGetOverlappedResult";
      break;
    case 0x2Cu:
      result = "WSAGetQOSByName";
      break;
    case 0x2Du:
      result = "WSAGetServiceClassInfoA";
      break;
    case 0x2Eu:
      result = "WSAGetServiceClassInfoW";
      break;
    case 0x2Fu:
      result = "WSAGetServiceClassNameByClassIdA";
      break;
    case 0x30u:
      result = "WSAGetServiceClassNameByClassIdW";
      break;
    case 0x31u:
      result = "WSAHtonl";
      break;
    case 0x32u:
      result = "WSAHtons";
      break;
    case 0x33u:
      result = "gethostbyaddr";
      break;
    case 0x34u:
      result = "gethostbyname";
      break;
    case 0x35u:
      result = "getprotobyname";
      break;
    case 0x36u:
      result = "getprotobynumber";
      break;
    case 0x37u:
      result = "getservbyname";
      break;
    case 0x38u:
      result = "getservbyport";
      break;
    case 0x39u:
      result = "gethostname";
      break;
    case 0x3Au:
      result = "WSAInstallServiceClassA";
      break;
    case 0x3Bu:
      result = "WSAInstallServiceClassW";
      break;
    case 0x3Cu:
      result = "WSAIoctl";
      break;
    case 0x3Du:
      result = "WSAJoinLeaf";
      break;
    case 0x3Eu:
      result = "WSALookupServiceBeginA";
      break;
    case 0x3Fu:
      result = "WSALookupServiceBeginW";
      break;
    case 0x40u:
      result = "WSALookupServiceEnd";
      break;
    case 0x41u:
      result = "WSALookupServiceNextA";
      break;
    case 0x42u:
      result = "WSALookupServiceNextW";
      break;
    case 0x43u:
      result = "WSANSPIoctl";
      break;
    case 0x44u:
      result = "WSANtohl";
      break;
    case 0x45u:
      result = "WSANtohs";
      break;
    case 0x46u:
      result = "WSAProviderConfigChange";
      break;
    case 0x47u:
      result = "WSARecv";
      break;
    case 0x48u:
      result = "WSARecvDisconnect";
      break;
    case 0x49u:
      result = "WSARecvFrom";
      break;
    case 0x4Au:
      result = "WSARemoveServiceClass";
      break;
    case 0x4Bu:
      result = "WSAResetEvent";
      break;
    case 0x4Cu:
      result = "WSASend";
      break;
    case 0x4Du:
      result = "WSASendDisconnect";
      break;
    case 0x4Eu:
      result = "WSASendTo";
      break;
    case 0x4Fu:
      result = "WSASetEvent";
      break;
    case 0x50u:
      result = "WSASetServiceA";
      break;
    case 0x51u:
      result = "WSASetServiceW";
      break;
    case 0x52u:
      result = "WSASocketA";
      break;
    case 0x53u:
      result = "WSASocketW";
      break;
    case 0x54u:
      result = "WSAStringToAddressA";
      break;
    case 0x55u:
      result = "WSAStringToAddressW";
      break;
    case 0x56u:
      result = "WSAWaitForMultipleEvents";
      break;
    case 0x57u:
      result = "WSCDeinstallProvider";
      break;
    case 0x58u:
      result = "WSCEnableNSProvider";
      break;
    case 0x59u:
      result = "WSCEnumProtocols";
      break;
    case 0x5Au:
      result = "WSCGetProviderPath";
      break;
    case 0x5Bu:
      result = "WSCInstallNameSpace";
      break;
    case 0x5Cu:
      result = "WSCInstallProvider";
      break;
    case 0x5Du:
      result = "WSCUnInstallNameSpace";
      break;
    case 0x5Eu:
      result = "WSCUpdateProvider";
      break;
    case 0x5Fu:
      result = "WSCWriteNameSpaceOrder";
      break;
    case 0x60u:
      result = "WSCWriteProviderOrder";
      break;
    case 0x61u:
      result = "freeaddrinfo";
      break;
    case 0x62u:
      result = "getaddrinfo";
      break;
    case 0x63u:
      result = "getnameinfo";
      break;
    case 0x65u:
      result = "WSAAsyncSelect";
      break;
    case 0x66u:
      result = "WSAAsyncGetHostByAddr";
      break;
    case 0x67u:
      result = "WSAAsyncGetHostByName";
      break;
    case 0x68u:
      result = "WSAAsyncGetProtoByNumber";
      break;
    case 0x69u:
      result = "WSAAsyncGetProtoByName";
      break;
    case 0x6Au:
      result = "WSAAsyncGetServByPort";
      break;
    case 0x6Bu:
      result = "WSAAsyncGetServByName";
      break;
    case 0x6Cu:
      result = "WSACancelAsyncRequest";
      break;
    case 0x6Du:
      result = "WSASetBlockingHook";
      break;
    case 0x6Eu:
      result = "WSAUnhookBlockingHook";
      break;
    case 0x6Fu:
      result = "WSAGetLastError";
      break;
    case 0x70u:
      result = "WSASetLastError";
      break;
    case 0x71u:
      result = "WSACancelBlockingCall";
      break;
    case 0x72u:
      result = "WSAIsBlocking";
      break;
    case 0x73u:
      result = "WSAStartup";
      break;
    case 0x74u:
      result = "WSACleanup";
      break;
    case 0x97u:
      result = "__WSAFDIsSet";
      break;
    default:
      return NULL;
  }
  return result;
}
