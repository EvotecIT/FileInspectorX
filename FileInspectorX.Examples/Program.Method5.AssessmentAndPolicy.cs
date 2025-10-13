using FileInspectorX;

/// <summary>
/// Example 5: Assessment and vendor allow-list policy.
/// </summary>
internal static partial class Program
{
    public static void Method5_AssessmentAndPolicy(string path)
    {
        Console.WriteLine("[5] Assessment + Policy\n-------------------------");

        // Set an allow-list for vendors (package/signers)
        Settings.AllowedVendors = new[] { "Microsoft", "YourCompany" };
        Settings.VendorMatchMode = VendorMatchMode.Contains;

        var a = FileInspector.Analyze(path);
        var assess = a.Assessment ?? FileInspector.Assess(a);
        Console.WriteLine($"Decision={assess.Decision} Score={assess.Score} Codes={string.Join(",", assess.Codes)}");
        Console.WriteLine("Factors:");
        foreach (var kv in assess.Factors) Console.WriteLine($"  {kv.Key} => {kv.Value}");
    }
}

