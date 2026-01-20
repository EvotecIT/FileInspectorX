using System.Runtime.InteropServices;
using ComTypes = System.Runtime.InteropServices.ComTypes;

namespace FileInspectorX.Win32;

internal static class PropertySystemNative
{
    internal const int S_OK = 0;

    [Flags]
    internal enum GETPROPERTYSTOREFLAGS : uint
    {
        GPS_DEFAULT = 0x00000000,
        GPS_OPENSLOWITEM = 0x00000010,
        GPS_BESTEFFORT = 0x00000040
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    internal static extern int SHGetPropertyStoreFromParsingName(
        string pszPath,
        IntPtr pbc,
        GETPROPERTYSTOREFLAGS flags,
        ref Guid riid,
        out IPropertyStore? ppv);

    [DllImport("propsys.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    internal static extern int PSGetNameFromPropertyKey(ref PROPERTYKEY propkey, out IntPtr ppszCanonicalName);

    [DllImport("propsys.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    internal static extern int PSGetPropertyDescription(ref PROPERTYKEY propkey, ref Guid riid, out IPropertyDescription? ppv);

    [DllImport("propsys.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    internal static extern int PSGetPropertyDescriptionListFromString(string pszPropList, ref Guid riid, out IPropertyDescriptionList? ppv);

    [DllImport("ole32.dll")]
    internal static extern int PropVariantClear(ref PROPVARIANT pvar);

    [ComImport]
    [Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPropertyStore
    {
        [PreserveSig] int GetCount(out uint cProps);
        [PreserveSig] int GetAt(uint iProp, out PROPERTYKEY pkey);
        [PreserveSig] int GetValue(ref PROPERTYKEY key, out PROPVARIANT pv);
        [PreserveSig] int SetValue(ref PROPERTYKEY key, ref PROPVARIANT propvar);
        [PreserveSig] int Commit();
    }

    [ComImport]
    [Guid("6F79D558-3E96-4549-A1D1-7D75D2288814")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPropertyDescription
    {
        [PreserveSig] int GetPropertyKey(out PROPERTYKEY pkey);
        [PreserveSig] int GetCanonicalName(out IntPtr ppszName);
        [PreserveSig] int GetPropertyType(out ushort pvartype);
        [PreserveSig] int GetDisplayName(out IntPtr ppszDisplayName);
    }

    [ComImport]
    [Guid("1F9FC1D0-C39B-4B26-817F-011967D3440E")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPropertyDescriptionList
    {
        [PreserveSig] int GetCount(out uint pcElem);
        [PreserveSig] int GetAt(uint iElem, ref Guid riid, out IPropertyDescription? ppv);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROPERTYKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CALPWSTR
    {
        public uint cElems;
        public IntPtr pElems;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CABSTR
    {
        public uint cElems;
        public IntPtr pElems;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PROPVARIANT : IDisposable
    {
        private const uint MaxVectorElements = 10000;
        [FieldOffset(0)] private ushort vt;
        [FieldOffset(8)] private IntPtr pointerValue;
        [FieldOffset(8)] private int intValue;
        [FieldOffset(8)] private uint uintValue;
        [FieldOffset(8)] private long longValue;
        [FieldOffset(8)] private ulong ulongValue;
        [FieldOffset(8)] private short boolValue;
        [FieldOffset(8)] private short shortValue;
        [FieldOffset(8)] private ushort ushortValue;
        [FieldOffset(8)] private byte byteValue;
        [FieldOffset(8)] private sbyte sbyteValue;
        [FieldOffset(8)] private float floatValue;
        [FieldOffset(8)] private double doubleValue;
        [FieldOffset(8)] private ComTypes.FILETIME fileTime;
        [FieldOffset(8)] private CALPWSTR calpwstr;
        [FieldOffset(8)] private CABSTR cabstr;

        internal VarEnum VarType => (VarEnum)vt;

        internal string GetVarTypeString()
        {
            var vtVal = (VarEnum)vt;
            if ((vtVal & VarEnum.VT_VECTOR) == VarEnum.VT_VECTOR)
            {
                var baseType = (VarEnum)((ushort)vtVal & ~(ushort)VarEnum.VT_VECTOR);
                return $"VT_VECTOR|{baseType}";
            }
            return vtVal.ToString();
        }

        internal object? GetValue()
        {
            var vtVal = (VarEnum)vt;
            if (vtVal == VarEnum.VT_EMPTY || vtVal == VarEnum.VT_NULL) return null;

            if ((vtVal & VarEnum.VT_VECTOR) == VarEnum.VT_VECTOR)
            {
                var baseType = (VarEnum)((ushort)vtVal & ~(ushort)VarEnum.VT_VECTOR);
                switch (baseType)
                {
                    case VarEnum.VT_LPWSTR:
                        return ReadStringVector(calpwstr, useBstr: false);
                    case VarEnum.VT_BSTR:
                        return ReadStringVector(cabstr, useBstr: true);
                    default:
                        return null;
                }
            }

            switch (vtVal)
            {
                case VarEnum.VT_LPWSTR:
                    return Marshal.PtrToStringUni(pointerValue);
                case VarEnum.VT_BSTR:
                    return Marshal.PtrToStringBSTR(pointerValue);
                case VarEnum.VT_LPSTR:
                    return Marshal.PtrToStringAnsi(pointerValue);
                case VarEnum.VT_UI4:
                    return uintValue;
                case VarEnum.VT_I4:
                    return intValue;
                case VarEnum.VT_UI8:
                    return ulongValue;
                case VarEnum.VT_I8:
                    return longValue;
                case VarEnum.VT_UI2:
                    return ushortValue;
                case VarEnum.VT_I2:
                    return shortValue;
                case VarEnum.VT_UI1:
                    return byteValue;
                case VarEnum.VT_I1:
                    return sbyteValue;
                case VarEnum.VT_BOOL:
                    return boolValue != 0;
                case VarEnum.VT_FILETIME:
                    return FileTimeToDateTime(fileTime);
                case VarEnum.VT_DATE:
                    return DateTime.FromOADate(doubleValue);
                case VarEnum.VT_R8:
                    return doubleValue;
                case VarEnum.VT_R4:
                    return floatValue;
                default:
                    return null;
            }
        }

        private static string[] ReadStringVector(CALPWSTR ca, bool useBstr)
        {
            if (ca.cElems == 0 || ca.pElems == IntPtr.Zero) return Array.Empty<string>();
            if (ca.cElems > MaxVectorElements) return Array.Empty<string>();
            var arr = new string[ca.cElems];
            for (var i = 0; i < ca.cElems; i++)
            {
                var ptr = Marshal.ReadIntPtr(ca.pElems, i * IntPtr.Size);
                arr[i] = useBstr ? (Marshal.PtrToStringBSTR(ptr) ?? string.Empty) : (Marshal.PtrToStringUni(ptr) ?? string.Empty);
            }
            return arr;
        }

        private static string[] ReadStringVector(CABSTR ca, bool useBstr)
        {
            if (ca.cElems == 0 || ca.pElems == IntPtr.Zero) return Array.Empty<string>();
            if (ca.cElems > MaxVectorElements) return Array.Empty<string>();
            var arr = new string[ca.cElems];
            for (var i = 0; i < ca.cElems; i++)
            {
                var ptr = Marshal.ReadIntPtr(ca.pElems, i * IntPtr.Size);
                arr[i] = useBstr ? (Marshal.PtrToStringBSTR(ptr) ?? string.Empty) : (Marshal.PtrToStringUni(ptr) ?? string.Empty);
            }
            return arr;
        }

        private static DateTime? FileTimeToDateTime(ComTypes.FILETIME ft)
        {
            long ticks = ((long)ft.dwHighDateTime << 32) | ((long)(uint)ft.dwLowDateTime);
            if (ticks <= 0) return null;
            try
            {
                return DateTime.FromFileTimeUtc(ticks).ToLocalTime();
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            _ = PropVariantClear(ref this);
        }
    }
}
