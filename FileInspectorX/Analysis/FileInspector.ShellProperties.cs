using System.Globalization;
using System.Runtime.InteropServices;
using FileInspectorX.Win32;

namespace FileInspectorX;

public static partial class FileInspector
{
    private const string FullDetailsPropList = "System.PropList.FullDetails";

    /// <summary>
    /// Reads Windows shell properties (Explorer Details) for a file. Returns empty on non-Windows platforms or errors.
    /// </summary>
    public static IReadOnlyList<ShellProperty> ReadShellProperties(string path, ShellPropertiesOptions? options = null)
    {
        options ??= new ShellPropertiesOptions();
        if (string.IsNullOrWhiteSpace(path)) return Array.Empty<ShellProperty>();
        if (!File.Exists(path)) return Array.Empty<ShellProperty>();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return Array.Empty<ShellProperty>();

        try
        {
            var iid = typeof(PropertySystemNative.IPropertyStore).GUID;
            var flags = PropertySystemNative.GETPROPERTYSTOREFLAGS.GPS_BESTEFFORT |
                        PropertySystemNative.GETPROPERTYSTOREFLAGS.GPS_OPENSLOWITEM;
            var hr = PropertySystemNative.SHGetPropertyStoreFromParsingName(path, IntPtr.Zero, flags, ref iid, out var store);
            if (hr != PropertySystemNative.S_OK || store == null) return Array.Empty<ShellProperty>();

            var list = new List<ShellProperty>();
            try
            {
                var keys = new List<PropertySystemNative.PROPERTYKEY>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (options.IncludeEmpty)
                {
                    foreach (var key in GetPropertyListKeys(FullDetailsPropList))
                        TryAddKey(keys, seen, key);
                }

                if (store.GetCount(out var count) == PropertySystemNative.S_OK)
                {
                    for (uint i = 0; i < count; i++)
                    {
                        if (store.GetAt(i, out var key) != PropertySystemNative.S_OK) continue;
                        TryAddKey(keys, seen, key);
                    }
                }

                for (var i = 0; i < keys.Count; i++)
                {
                    var key = keys[i];
                    var pv = new PropertySystemNative.PROPVARIANT();
                    try
                    {
                        var hrVal = store.GetValue(ref key, out pv);
                        var valueText = hrVal == PropertySystemNative.S_OK ? FormatShellValue(pv.GetValue()) : null;
                        if (string.IsNullOrWhiteSpace(valueText))
                        {
                            if (!options.IncludeEmpty) continue;
                            valueText = string.Empty;
                        }

                        var canonicalName = TryGetCanonicalName(key);
                        var displayName = TryGetDisplayName(key);
                        var resolvedDisplay = displayName ?? canonicalName ?? FormatPropertyKey(key);

                        list.Add(new ShellProperty
                        {
                            DisplayName = resolvedDisplay,
                            CanonicalName = canonicalName,
                            Value = valueText,
                            ValueType = pv.GetVarTypeString(),
                            Key = FormatPropertyKey(key)
                        });
                    }
                    finally
                    {
                        pv.Dispose();
                    }
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(store);
            }
            return list;
        }
        catch (Exception ex)
        {
            if (Settings.Logger.IsWarning)
                Settings.Logger.WriteWarning("shellprops:read failed ({0})", ex.GetType().Name);
            else if (Settings.Logger.IsDebug)
                Settings.Logger.WriteDebug("shellprops:read failed ({0})", ex.GetType().Name);
            return Array.Empty<ShellProperty>();
        }
    }

    private static string FormatPropertyKey(PropertySystemNative.PROPERTYKEY key)
    {
        return $"{key.fmtid}:{key.pid}";
    }

    private static void TryAddKey(List<PropertySystemNative.PROPERTYKEY> keys, HashSet<string> seen, PropertySystemNative.PROPERTYKEY key)
    {
        var id = FormatPropertyKey(key);
        if (seen.Add(id)) keys.Add(key);
    }

    private static string? TryGetCanonicalName(PropertySystemNative.PROPERTYKEY key)
    {
        try
        {
            var hr = PropertySystemNative.PSGetNameFromPropertyKey(ref key, out var ptr);
            if (hr != PropertySystemNative.S_OK || ptr == IntPtr.Zero) return null;
            try
            {
                return Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                Marshal.FreeCoTaskMem(ptr);
            }
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetDisplayName(PropertySystemNative.PROPERTYKEY key)
    {
        try
        {
            var iid = typeof(PropertySystemNative.IPropertyDescription).GUID;
            var hr = PropertySystemNative.PSGetPropertyDescription(ref key, ref iid, out var desc);
            if (hr != PropertySystemNative.S_OK || desc == null) return null;
            try
            {
                var hr2 = desc.GetDisplayName(out var ptr);
                if (hr2 != PropertySystemNative.S_OK || ptr == IntPtr.Zero) return null;
                try
                {
                    return Marshal.PtrToStringUni(ptr);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(ptr);
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(desc);
            }
        }
        catch
        {
            return null;
        }
    }

    private static List<PropertySystemNative.PROPERTYKEY> GetPropertyListKeys(string propList)
    {
        var keys = new List<PropertySystemNative.PROPERTYKEY>();
        var iid = typeof(PropertySystemNative.IPropertyDescriptionList).GUID;
        var hr = PropertySystemNative.PSGetPropertyDescriptionListFromString(propList, ref iid, out var list);
        if (hr != PropertySystemNative.S_OK || list == null) return keys;
        try
        {
            if (list.GetCount(out var count) != PropertySystemNative.S_OK) return keys;
            var iidDesc = typeof(PropertySystemNative.IPropertyDescription).GUID;
            for (uint i = 0; i < count; i++)
            {
                if (list.GetAt(i, ref iidDesc, out var desc) != PropertySystemNative.S_OK || desc == null) continue;
                try
                {
                    if (desc.GetPropertyKey(out var key) == PropertySystemNative.S_OK)
                        keys.Add(key);
                }
                finally
                {
                    Marshal.FinalReleaseComObject(desc);
                }
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(list);
        }
        return keys;
    }

    private static string? FormatShellValue(object? value)
    {
        if (value == null) return null;
        if (value is string s) return s;
        if (value is string[] arr)
        {
            var parts = new List<string>(arr.Length);
            foreach (var item in arr)
            {
                if (!string.IsNullOrWhiteSpace(item)) parts.Add(item);
            }
            return parts.Count == 0 ? null : string.Join("; ", parts);
        }
        if (value is bool b) return b ? "Yes" : "No";
        if (value is DateTime dt) return dt.ToString("G", CultureInfo.CurrentCulture);
        if (value is IFormattable f) return f.ToString(null, CultureInfo.CurrentCulture);
        return value.ToString();
    }
}
