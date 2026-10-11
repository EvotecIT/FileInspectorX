param([Parameter(Mandatory)] [string] $ModulePath)

BeforeAll {
    Import-Module $ModulePath -ErrorAction Stop
    $flags = [Reflection.BindingFlags]'Static,NonPublic'
    $type = [FileInspectorX.Prototypes.FileSystem.MftSnapshot].Assembly.GetType('FileInspectorX.Prototypes.FileSystem.NtfsFileRecordParser')
    $parse = $type.GetMethod('Parse', $flags)
    function Field($record, [string] $name) { $record.GetType().GetField($name, [Reflection.BindingFlags]'Instance,NonPublic').GetValue($record) }
    function Attribute([uint32] $type, [byte[]] $value) {
        $length = [int]([Math]::Ceiling((24 + $value.Length) / 8) * 8)
        $bytes = [byte[]]::new($length)
        [BitConverter]::GetBytes($type).CopyTo($bytes, 0)
        [BitConverter]::GetBytes([uint32]$length).CopyTo($bytes, 4)
        [BitConverter]::GetBytes([uint32]$value.Length).CopyTo($bytes, 16)
        [BitConverter]::GetBytes([uint16]24).CopyTo($bytes, 20)
        $value.CopyTo($bytes, 24)
        return ,$bytes
    }
    function NameAttribute([string] $name, [byte] $namespace = 1) {
        $value = [byte[]]::new(66 + $name.Length * 2)
        [BitConverter]::GetBytes([uint64]0x5678000000000020).CopyTo($value, 0)
        $value[64] = [byte]$name.Length; $value[65] = $namespace
        [Text.Encoding]::Unicode.GetBytes($name).CopyTo($value, 66)
        return ,(Attribute 0x30 $value)
    }
    function New-FileRecord([switch] $Nonresident) {
        $bytes = [byte[]]::new(1036)
        [BitConverter]::GetBytes([uint64]0x42).CopyTo($bytes, 0)
        [BitConverter]::GetBytes([uint32]1024).CopyTo($bytes, 8)
        [Text.Encoding]::ASCII.GetBytes('FILE').CopyTo($bytes, 12)
        [BitConverter]::GetBytes([uint16]48).CopyTo($bytes, 16)
        [BitConverter]::GetBytes([uint16]3).CopyTo($bytes, 18)
        [BitConverter]::GetBytes([uint16]0x1234).CopyTo($bytes, 28)
        [BitConverter]::GetBytes([uint16]2).CopyTo($bytes, 30)
        [BitConverter]::GetBytes([uint16]56).CopyTo($bytes, 32)
        [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 34)
        [BitConverter]::GetBytes([uint32]1024).CopyTo($bytes, 40)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($bytes, 60)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($bytes, 522)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($bytes, 1034)
        $si = [byte[]]::new(48)
        foreach ($offset in @(0,8,16,24)) { [BitConverter]::GetBytes([datetime]::Parse('2020-01-02T03:04:05Z').ToUniversalTime().ToFileTimeUtc()).CopyTo($si,$offset) }
        [BitConverter]::GetBytes([uint32]32).CopyTo($si, 32)
        $data = Attribute 0x80 ([byte[]](1,2,3,4,5))
        if ($Nonresident) {
            $data = [byte[]]::new(64)
            [BitConverter]::GetBytes([uint32]0x80).CopyTo($data,0)
            [BitConverter]::GetBytes([uint32]64).CopyTo($data,4)
            $data[8] = 1
            [BitConverter]::GetBytes([long]8589934592).CopyTo($data,48)
        }
        $position = 68
        foreach ($attribute in @((Attribute 0x10 $si), (NameAttribute 'file-ż.txt'), (NameAttribute 'alias.txt'), (NameAttribute 'FILE~1.TXT' 2), $data)) {
            $attribute.CopyTo($bytes,$position); $position += $attribute.Length
        }
        [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes,$position)
        [BitConverter]::GetBytes([uint32]($position + 4 - 12)).CopyTo($bytes,36)
        foreach ($i in @(1,2)) {
            [Array]::Copy($bytes, 12 + $i * 512 - 2, $bytes, 60 + $i * 2, 2)
            [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($bytes,12 + $i * 512 - 2)
        }
        return ,$bytes
    }
    function Read-Record([byte[]] $bytes) { $parse.Invoke($null, [object[]]@($bytes, $bytes.Length, 512)) }
}

Describe 'Direct NTFS metadata and link decoding' {
    It 'preserves full identities, all long-name aliases, timestamps and resident logical length' {
        $record = Read-Record (New-FileRecord)
        (Field $record Id) | Should -Be ([uint64]0x1234000000000042)
        (Field $record Length) | Should -Be 5
        (Field $record Created) | Should -Be ([datetime]::Parse('2020-01-02T03:04:05Z').ToUniversalTime())
        $links = @(Field $record Links)
        $links.Count | Should -Be 2
        (Field $links[0] Name) | Should -BeExactly 'file-ż.txt'
        (Field $links[1] ParentId) | Should -Be ([uint64]0x5678000000000020)
    }
    It 'uses the 64-bit unnamed data size for nonresident data' {
        (Field (Read-Record (New-FileRecord -Nonresident)) Length) | Should -Be 8589934592
    }
    It 'accepts already repaired API output and rejects torn sector fixups' {
        $bytes = New-FileRecord
        $null = Read-Record $bytes
        { Read-Record $bytes } | Should -Not -Throw
        $bytes[1034] = 0x55
        { Read-Record $bytes } | Should -Throw
    }
    It 'rejects an escaping resident attribute and missing terminator' {
        $bytes = New-FileRecord
        [BitConverter]::GetBytes([uint32]65535).CopyTo($bytes,84)
        { Read-Record $bytes } | Should -Throw
        $bytes = New-FileRecord
        $used = [BitConverter]::ToUInt32($bytes,36)
        [BitConverter]::GetBytes([uint32]0).CopyTo($bytes,12+$used-4)
        { Read-Record $bytes } | Should -Throw
    }
    It 'rejects invalid geometry and truncated response lengths' {
        $bytes = New-FileRecord
        { $parse.Invoke($null, [object[]]@($bytes, 100, 512)) } | Should -Throw
        { $parse.Invoke($null, [object[]]@($bytes, $bytes.Length, 4096)) } | Should -Throw
    }
    It 'validates extension ownership using sequence-qualified base identity' {
        $owner = Read-Record (New-FileRecord)
        $extension = Read-Record (New-FileRecord)
        $extension.GetType().GetField('BaseId',[Reflection.BindingFlags]'Instance,NonPublic').SetValue($extension,[uint64]0x2345000000000042)
        $merge = $owner.GetType().GetMethod('Merge',[Reflection.BindingFlags]'Instance,NonPublic')
        { $merge.Invoke($owner,[object[]]@($extension)) } | Should -Throw
    }
    It 'rejects traversal names and invalid timestamps rather than fabricating metadata' {
        $bytes = New-FileRecord
        # First name begins after the standard-information attribute.
        $firstName = 68 + 72 + 24
        $bytes[$firstName+64] = 2
        [Text.Encoding]::Unicode.GetBytes('..').CopyTo($bytes,$firstName+66)
        { Read-Record $bytes } | Should -Throw
        $bytes = New-FileRecord
        [BitConverter]::GetBytes([long]::MaxValue).CopyTo($bytes,68+24)
        { Read-Record $bytes } | Should -Throw
    }
}
