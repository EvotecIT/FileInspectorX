param([Parameter(Mandatory)] [string] $ModulePath)

BeforeAll {
    Import-Module $ModulePath -ErrorAction Stop
    $assembly = [FileInspectorX.Prototypes.FileSystem.MftSnapshot].Assembly
    $parser = $assembly.GetType('FileInspectorX.Prototypes.FileSystem.UsnRecordParser').GetMethod('Parse', [Reflection.BindingFlags]'Static,NonPublic')
    function New-UsnBuffer([string] $name = 'file.txt') {
        $nameBytes = [Text.Encoding]::Unicode.GetBytes($name)
        $recordLength = [int]([Math]::Ceiling((60 + $nameBytes.Length) / 8) * 8)
        $buffer = [byte[]]::new(8 + $recordLength)
        [BitConverter]::GetBytes([uint32]$recordLength).CopyTo($buffer, 8)
        [BitConverter]::GetBytes([uint16]2).CopyTo($buffer, 12)
        [BitConverter]::GetBytes([uint64]0x1234000000000042).CopyTo($buffer, 16)
        [BitConverter]::GetBytes([uint64]0x5678000000000020).CopyTo($buffer, 24)
        [BitConverter]::GetBytes([uint16]$nameBytes.Length).CopyTo($buffer, 64)
        [BitConverter]::GetBytes([uint16]60).CopyTo($buffer, 66)
        $nameBytes.CopyTo($buffer, 68)
        return ,$buffer
    }
    function Read-Usn($buffer, [int] $returned = -1, [Threading.CancellationToken] $token = [Threading.CancellationToken]::None) {
        if ($returned -eq -1) { $returned = $buffer.Length }
        $records = $parser.Invoke($null, [object[]]@($buffer, $returned, $token))
        foreach ($record in $records) { $record }
    }
}

Describe 'Windows MFT enumeration record contract' {
    It 'preserves Unicode names and all 64 identity bits including sequence numbers' {
        $name = 'file-' + [char]0x017C + '.txt'
        $records = @(Read-Usn (New-UsnBuffer $name))
        $records.Count | Should -Be 1
        $flags = [Reflection.BindingFlags]'Instance,NonPublic'
        $records[0].GetType().GetProperty('Name', $flags).GetValue($records[0]) | Should -BeExactly $name
        $records[0].GetType().GetProperty('Id', $flags).GetValue($records[0]) | Should -Be ([uint64]0x1234000000000042)
        $records[0].GetType().GetProperty('ParentId', $flags).GetValue($records[0]) | Should -Be ([uint64]0x5678000000000020)
    }
    It 'rejects truncated headers and record lengths instead of reading outside the returned bytes' {
        $buffer = New-UsnBuffer
        { Read-Usn $buffer 7 } | Should -Throw
        { Read-Usn $buffer ($buffer.Length - 8) } | Should -Throw
        [BitConverter]::GetBytes([uint32]0).CopyTo($buffer, 8)
        { Read-Usn $buffer } | Should -Throw
    }
    It 'rejects an unsupported record layout rather than decoding it as V2' {
        $buffer = New-UsnBuffer
        [BitConverter]::GetBytes([uint16]3).CopyTo($buffer, 12)
        { Read-Usn $buffer } | Should -Throw
    }
    It 'rejects filename ranges that escape the record or split a UTF16 character' {
        $buffer = New-UsnBuffer
        [BitConverter]::GetBytes([uint16]65534).CopyTo($buffer, 66)
        { Read-Usn $buffer } | Should -Throw
        $buffer = New-UsnBuffer
        [BitConverter]::GetBytes([uint16]3).CopyTo($buffer, 64)
        { Read-Usn $buffer } | Should -Throw
    }
    It 'rejects path traversal and rooted components before metadata hydration' {
        foreach ($name in @('..', '.', '..\outside', 'D:outside', '/outside')) {
            { Read-Usn (New-UsnBuffer $name) } | Should -Throw
        }
    }
    It 'stops parsing a batch when cancellation arrives after enumeration begins' {
        $source = [Threading.CancellationTokenSource]::new()
        try {
            $buffer = New-UsnBuffer
            $records = $parser.Invoke($null, [object[]]@($buffer, $buffer.Length, $source.Token))
            $source.Cancel()
            { foreach ($record in $records) { $record } } | Should -Throw
        } finally { $source.Dispose() }
    }
}
