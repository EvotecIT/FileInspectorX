param([Parameter(Mandatory)] [string] $RequestFile)
$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$scratch = [IO.Path]::GetFullPath($env:EVOTEC_SCRATCH_ROOT).TrimEnd('\') + '\'
foreach ($path in @($RequestFile, $request.FixtureRoot, $request.OutputRoot)) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not [IO.Path]::GetFullPath($path).StartsWith($scratch, [StringComparison]::OrdinalIgnoreCase)) { throw 'Probe paths must be within configured mounted scratch.' }
    for ($ancestor = $path; $ancestor; $ancestor = Split-Path $ancestor -Parent) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse ancestors are not accepted.' }
    }
}
if (-not (Test-Path -LiteralPath $request.FixtureRoot -PathType Container) -or -not (Test-Path -LiteralPath $request.OutputRoot -PathType Container)) { throw 'Existing mounted fixture and output directories required.' }
$output = Join-Path $request.OutputRoot 'raw-read-probe.json'
if (Test-Path -LiteralPath $output) { throw 'Probe output already exists.' }
$env:TEMP = Join-Path (Split-Path $RequestFile -Parent) 'temp'
$env:TMP = $env:TEMP
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class FileInspectorXRawReadProbe {
 public sealed class Result {
  public string Device {get;set;} public uint Share {get;set;} public int Requested {get;set;}
  public bool Aligned {get;set;} public bool Success {get;set;} public int Error {get;set;}
  public uint BytesRead {get;set;} public string Signature {get;set;}
 }
 public static Result[] Run(string root) {
  var guid = new StringBuilder(1024);
  if (!GetVolumeNameForVolumeMountPointW(root,guid,guid.Capacity)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  var results = new List<Result>();
  foreach(var device in new[]{@"\\.\"+root.TrimEnd('\\'),guid.ToString().TrimEnd('\\')})
   foreach(uint share in new uint[]{3,7}) foreach(int length in new[]{512,4096}) foreach(bool aligned in new[]{false,true}) {
    var result = new Result {Device=device,Share=share,Requested=length,Aligned=aligned};
    using(var handle=CreateFileW(device,0x80000000,share,IntPtr.Zero,3,0,IntPtr.Zero)) {
     if(handle.IsInvalid) result.Error=Marshal.GetLastWin32Error();
     else {
      var allocation=Marshal.AllocHGlobal(length+65536);
      try {
       var buffer=aligned?new IntPtr((allocation.ToInt64()+65535)&~65535L):new IntPtr(allocation.ToInt64()+1);
       uint read; result.Success=ReadFile(handle,buffer,(uint)length,out read,IntPtr.Zero);
       result.Error=result.Success?0:Marshal.GetLastWin32Error(); result.BytesRead=read;
       if(result.Success && read>=11) {var signature=new byte[8];Marshal.Copy(new IntPtr(buffer.ToInt64()+3),signature,0,8);result.Signature=Encoding.ASCII.GetString(signature);}
      } finally {Marshal.FreeHGlobal(allocation);}
     }
    }
    results.Add(result);
   }
  return results.ToArray();
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string n,uint a,uint s,IntPtr x,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ReadFile(SafeFileHandle h,IntPtr p,uint c,out uint r,IntPtr o);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumeNameForVolumeMountPointW(string n,StringBuilder b,int c);
}
'@
$root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($request.FixtureRoot))
[FileInspectorXRawReadProbe]::Run($root) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $output
