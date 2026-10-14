using OfficeIMO.Excel;
using OfficeIMO.OpenDocument;
using OfficeIMO.PowerPoint;
using OfficeIMO.Rtf;
using OfficeIMO.Word;

namespace FileInspectorX.OfficeIMO.Tests;

/// <summary>Native owner APIs author synthetic inert inputs; the adapter remains the only reader under test.</summary>
internal static partial class NativeFixtures
{
    internal const string Text = "Canonical invoices describe quarterly revenue and measured operating costs.";
    internal static readonly byte[] Pixel = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");

    internal static byte[] Word()
    {
        using WordDocument document = WordDocument.Create();
        document.AddParagraph(Text);
        return document.ToBytes();
    }
    internal static byte[] WordHeading(string heading)
    {
        using WordDocument document = WordDocument.Create();
        document.AddParagraph(heading).SetStyle(WordParagraphStyles.Heading1);
        return document.ToBytes();
    }
    internal static byte[] Excel()
    {
        using ExcelDocument document = ExcelDocument.Create();
        var sheet = document.AddWorksheet("Evidence");
        sheet.CellValue(1, 1, "Header"); sheet.CellValue(2, 1, Text); sheet.CellFormula(3, 1, "1+1");
        return document.ToBytes();
    }
    internal static byte[] ExcelStrings(int count)
    {
        using ExcelDocument document = ExcelDocument.Create();
        var sheet = document.AddWorksheet("Evidence");
        for (int index = 1; index <= count; index++) sheet.CellValue(index, 1, "Unique string " + index);
        return document.ToBytes();
    }
    internal static byte[] PowerPoint()
    {
        using PowerPointPresentation document = PowerPointPresentation.Create();
        document.AddSlide().AddTextBox(Text, 100000, 100000, 6000000, 500000);
        return document.ToBytes();
    }
    internal static byte[] Odf(bool image = false)
    {
        OdtDocument document = OdtDocument.Create();
        document.Metadata.Title = "Authored source title";
        var paragraph = document.AddParagraph(Text);
        if (image) paragraph.AddImage(Pixel, "pixel.png", OdfLength.Centimeters(1), OdfLength.Centimeters(1));
        return document.ToBytes();
    }
    internal static byte[] Rtf(bool image = false)
    {
        RtfDocument document = RtfDocument.Create();
        var paragraph = document.AddParagraph(Text);
        if (image) paragraph.AddImage(RtfImageFormat.Png, Pixel);
        return document.ToBytes();
    }
}
