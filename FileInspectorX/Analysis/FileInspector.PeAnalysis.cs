namespace FileInspectorX;

public static partial class FileInspector
{
    private static void AnalyzePe(InspectionInput input, FileAnalysis res)
    {
        var path = input.Name;
        // PE triage
        if (IsPe(input, out var peMachine, out var peSubsystem, out bool hasClr, out bool hasSec)) {
            if (hasSec) res.Flags |= ContentFlags.PeHasAuthenticodeDirectory;
            if (hasClr) res.Flags |= ContentFlags.PeIsDotNet;
            res.PeMachine = peMachine;
            res.PeSubsystem = peSubsystem;

            var ver = PeReader.TryExtractVersionStrings(input);
            if (ver != null && ver.Count > 0) res.VersionInfo = ver;
            if (PeReader.TryReadPe(input, out var peInfo)) {
                if ((peInfo.Characteristics & IMAGE_FILE_DLL) != 0)
                    res.PeKind = "dll";
                else if (peInfo.Subsystem == 1)
                    res.PeKind = "sys";
                else
                    res.PeKind = "exe";
                if (peInfo.Sections.Any(s => string.Equals(s.Name, "UPX0", StringComparison.OrdinalIgnoreCase) || string.Equals(s.Name, "UPX1", StringComparison.OrdinalIgnoreCase))) {
                    res.Flags |= ContentFlags.PeLooksPackedUpx;
                }
                // Hardening flags from DllCharacteristics
                var dc = peInfo.DllCharacteristics;
                bool hasAslr = (dc & 0x0040) != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                bool hasNx = (dc & 0x0100) != 0;   // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                bool hasCfg = (dc & 0x4000) != 0;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF (may require Win10 toolchain)
                bool hasHighEntropy = (dc & 0x0020) != 0; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
                if (!hasAslr) res.Flags |= ContentFlags.PeNoAslr;
                if (!hasNx) res.Flags |= ContentFlags.PeNoNx;
                if (!hasCfg) res.Flags |= ContentFlags.PeNoCfg;
                if (peInfo.IsPEPlus && !hasHighEntropy) res.Flags |= ContentFlags.PeNoHighEntropyVa;
                // .NET strong-name flag
                if (peInfo.DotNetStrongNameSigned.HasValue)
                    res.DotNetStrongNameSigned = peInfo.DotNetStrongNameSigned;
            }

            // DLL export quick signals: highlight COM registration exports
            try
            {
                var extLower = System.IO.Path.GetExtension(path)?.TrimStart('.').ToLowerInvariant();
                if (extLower is "dll" || extLower is "exe")
                {
                    if (PeReader.TryListExportNames(input, out var expNames) && expNames != null && expNames.Count > 0)
                    {
                        var list = new List<string>(res.SecurityFindings ?? Array.Empty<string>());
                        list.Add($"pe:exports={expNames.Count}");
                        // Common COM registration entry points
                        bool reg = false; foreach (var n in expNames) { var ln = n.ToLowerInvariant(); if (ln == "dllregisterserver" || ln == "dllinstall" || ln == "dllunregisterserver") { reg = true; break; } }
                        if (reg) list.Add("pe:regsvr");
                        // Top export names (3 max)
                        try { var top = string.Join(",", expNames.Take(3)); if (!string.IsNullOrWhiteSpace(top)) list.Add($"pe:top={top}"); } catch { }
                        res.SecurityFindings = list;
                    }
                }
            } catch { }
        }

        // Best-effort .NET TargetFramework detection for managed PE
        try
        {
            if ((res.Flags & ContentFlags.PeIsDotNet) != 0)
            {
                var tfm = TryDetectTargetFramework(input, OperationSettings.DetectionReadBudgetBytes);
                if (!string.IsNullOrWhiteSpace(tfm))
                {
                    var dict = res.VersionInfo != null ? new Dictionary<string,string>(res.VersionInfo.ToDictionary(kv => kv.Key, kv => kv.Value)) : new Dictionary<string,string>();
                    dict["TargetFramework"] = tfm!;
                    res.VersionInfo = dict;
                }
            }
        } catch { }

    }
}
