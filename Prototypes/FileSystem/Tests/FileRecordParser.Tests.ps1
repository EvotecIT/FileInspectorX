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
        for ($i = 0; $i -lt $name.Length; $i++) { [BitConverter]::GetBytes([uint16]$name[$i]).CopyTo($value, 66 + 2 * $i) }
        return ,(Attribute 0x30 $value)
    }
    function New-FileRecord([switch] $Nonresident, [switch] $OwnerWithoutNames, [switch] $ExtensionOnlyNames,
        [string] $FirstName = ('file-' + [char]0x017C + '.txt')) {
        $bytes = [byte[]]::new(1036)
        [BitConverter]::GetBytes([uint64]0x42).CopyTo($bytes, 0)
        [BitConverter]::GetBytes([uint32]1024).CopyTo($bytes, 8)
        [Text.Encoding]::ASCII.GetBytes('FILE').CopyTo($bytes, 12)
        [BitConverter]::GetBytes([uint16]48).CopyTo($bytes, 16)
        [BitConverter]::GetBytes([uint16]3).CopyTo($bytes, 18)
        [BitConverter]::GetBytes([uint16]0x1234).CopyTo($bytes, 28)
        [BitConverter]::GetBytes([uint16]3).CopyTo($bytes, 30)
        [BitConverter]::GetBytes([uint16]56).CopyTo($bytes, 32)
        [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 34)
        [BitConverter]::GetBytes([uint32]1024).CopyTo($bytes, 40)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($bytes, 60)
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
        $attributes = @()
        if (-not $ExtensionOnlyNames) { $attributes += ,(Attribute 0x10 $si) }
        if (-not $OwnerWithoutNames) { $attributes += @((NameAttribute $FirstName), (NameAttribute 'alias.txt'), (NameAttribute 'FILE~1.TXT' 2)) }
        if (-not $ExtensionOnlyNames) { $attributes += ,$data }
        if ($ExtensionOnlyNames) {
            [BitConverter]::GetBytes([uint64]0x43).CopyTo($bytes,0)
            [BitConverter]::GetBytes([uint64]0x1234000000000042).CopyTo($bytes,44)
            [BitConverter]::GetBytes([uint16]0).CopyTo($bytes,30)
        }
        foreach ($attribute in $attributes) {
            $attribute.CopyTo($bytes,$position); $position += $attribute.Length
        }
        [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes,$position)
        [BitConverter]::GetBytes([uint32]($position + 4 - 12)).CopyTo($bytes,36)
        foreach ($i in @(1,2)) {
            [Array]::Copy($bytes, 12 + $i * 512 - 2, $bytes, 60 + $i * 2, 2)
        }
        return ,$bytes
    }
    function Read-Record([byte[]] $bytes) { $parse.Invoke($null, [object[]]@($bytes, $bytes.Length, 512)) }
}

Describe 'Direct NTFS metadata and link decoding' {
    It 'preserves an unpaired surrogate in the stored NTFS name' {
        $name = 'file-' + [char]0xD800 + '.txt'
        $record = Read-Record (New-FileRecord -FirstName $name)
        $links = @(Field $record Links)
        (Field $links[0] Name) | Should -BeExactly $name
        [int](Field $links[0] Name)[5] | Should -Be 0xD800
    }
    It 'preserves full identities, all long-name aliases, timestamps and resident logical length' {
        $record = Read-Record (New-FileRecord)
        (Field $record Id) | Should -Be ([uint64]0x1234000000000042)
        (Field $record Length) | Should -Be 5
        (Field $record Created) | Should -Be ([datetime]::Parse('2020-01-02T03:04:05Z').ToUniversalTime())
        $links = @(Field $record Links)
        $links.Count | Should -Be 2
        (Field $record NameAttributeCount) | Should -Be (Field $record LinkCount)
        (Field $record NameAttributeCount) | Should -Be 3
        (Field $links[0] Name) | Should -BeExactly ('file-' + [char]0x017C + '.txt')
        (Field $links[1] Name) | Should -BeExactly 'alias.txt'
        (Field $links[1] ParentId) | Should -Be ([uint64]0x5678000000000020)
    }
    It 'uses the 64-bit unnamed data size for nonresident data' {
        (Field (Read-Record (New-FileRecord -Nonresident)) Length) | Should -Be 8589934592
    }
    It 'preserves high Windows attributes while excluding NTFS directory and index flags' {
        $bytes = New-FileRecord
        $attributes = [uint32]0x305C0020
        [BitConverter]::GetBytes($attributes).CopyTo($bytes, 124)
        [uint32](Field (Read-Record $bytes) Attributes) | Should -Be ([uint32]0x005C0020)
    }
    It 'fixes raw sector trailers before decoding the same logical metadata' {
        $logical = New-FileRecord
        $raw = [byte[]]::new(1024)
        [Array]::Copy($logical,12,$raw,0,1024)
        foreach ($end in @(510,1022)) { [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($raw,$end) }
        $rawParse = $type.GetMethod('ParseRaw',$flags)
        $record = $rawParse.Invoke($null,[object[]]@($raw,0,1024,[uint64]0x42,512))
        (Field $record Length) | Should -Be 5
        (Field $record Id) | Should -Be ([uint64]0x1234000000000042)
        @(Field $record Links).Count | Should -Be 2
        $raw[510] | Should -Be $logical[522]
    }
    It 'rejects a torn raw record without partially applying its fixups' {
        $logical = New-FileRecord
        $raw = [byte[]]::new(1024)
        [Array]::Copy($logical,12,$raw,0,1024)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($raw,510)
        [BitConverter]::GetBytes([uint16]0x1234).CopyTo($raw,1022)
        $original = [Convert]::ToBase64String($raw)
        { $type.GetMethod('ParseRaw',$flags).Invoke($null,[object[]]@($raw,0,1024,[uint64]0x42,512)) } | Should -Throw
        [Convert]::ToBase64String($raw) | Should -BeExactly $original
    }
    It 'skips unused raw slots while refusing invalid in-use signatures' {
        $rawParse = $type.GetMethod('ParseRaw',$flags)
        $rawParse.Invoke($null,[object[]]@([byte[]]::new(1024),0,1024,[uint64]42,512)) | Should -BeNullOrEmpty
        $bytes = [byte[]]::new(1024); $bytes[22]=1
        { $rawParse.Invoke($null,[object[]]@($bytes,0,1024,[uint64]42,512)) } | Should -Throw
    }
    It 'uses fixed 512-byte update-sequence strides on a 4KiB-sector volume' {
        $small=New-FileRecord
        $record=[byte[]]::new(4096)
        [Array]::Copy($small,12,$record,0,48)
        $used=[BitConverter]::ToUInt32($small,36)
        [Array]::Copy($small,68,$record,72,$used-56)
        [BitConverter]::GetBytes([uint16]9).CopyTo($record,6)
        [BitConverter]::GetBytes([uint16]72).CopyTo($record,20)
        [BitConverter]::GetBytes([uint32]($used+16)).CopyTo($record,24)
        [BitConverter]::GetBytes([uint32]4096).CopyTo($record,28)
        [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($record,48)
        for($i=1;$i -le 8;$i++) { [Array]::Copy($record,$i*512-2,$record,48+$i*2,2) }
        $logical=[byte[]]::new(4108)
        [BitConverter]::GetBytes([uint64]0x42).CopyTo($logical,0)
        [BitConverter]::GetBytes([uint32]4096).CopyTo($logical,8)
        $record.CopyTo($logical,12)
        (Field ($parse.Invoke($null,[object[]]@($logical,4108,4096))) Length) | Should -Be 5
        for($i=1;$i -le 8;$i++) { [BitConverter]::GetBytes([uint16]0xABCD).CopyTo($record,$i*512-2) }
        $decoded=$type.GetMethod('ParseRaw',$flags).Invoke($null,[object[]]@($record,0,4096,[uint64]0x42,4096))
        (Field $decoded Length) | Should -Be 5
        for($i=1;$i -le 8;$i++) { [BitConverter]::ToUInt16($record,$i*512-2) | Should -Be 0 }
    }
    It 'decodes signed fragmented runs and rejects sparse truncated or escaping mappings' {
        $runsType = [FileInspectorX.Prototypes.FileSystem.MftSnapshot].Assembly.GetType('FileInspectorX.Prototypes.FileSystem.NtfsDataRuns')
        $decode = $runsType.GetMethod('Decode',$flags)
        $bytes = [byte[]](0x11,3,10,0x11,2,0xFE,0)
        $runs = @($decode.Invoke($null,[object[]]@($bytes,0,$bytes.Length,[long]0,[long]4)))
        $runs.Count | Should -Be 2
        (Field $runs[0] Lcn) | Should -Be 10
        (Field $runs[1] Lcn) | Should -Be 8
        (Field $runs[1] Vcn) | Should -Be 3
        foreach ($bad in @([byte[]](1,3,0),[byte[]](0x11,3),[byte[]](0x11,6,10,0),[byte[]](0x11,3,0xFE,0))) {
            { $decode.Invoke($null,[object[]]@($bad,0,$bad.Length,[long]0,[long]4)) } | Should -Throw
        }
    }
    It 'preserves logical API bytes when update-sequence values are stale' {
        $bytes = New-FileRecord
        [BitConverter]::GetBytes([uint16]0).CopyTo($bytes,62)
        [BitConverter]::GetBytes([uint16]0).CopyTo($bytes,64)
        $original = [byte[]]$bytes.Clone()
        (Field (Read-Record $bytes) Length) | Should -Be 5
        [Convert]::ToBase64String($bytes) | Should -BeExactly ([Convert]::ToBase64String($original))
        $bytes[1034] = 0x55
        { Read-Record $bytes } | Should -Not -Throw
        [BitConverter]::GetBytes([uint16]1024).CopyTo($bytes,16)
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
        { $parse.Invoke($null, [object[]]@($bytes, $bytes.Length, 1)) } | Should -Throw
    }
    It 'validates extension ownership using sequence-qualified base identity' {
        $owner = Read-Record (New-FileRecord)
        $extension = Read-Record (New-FileRecord)
        $extension.GetType().GetField('BaseId',[Reflection.BindingFlags]'Instance,NonPublic').SetValue($extension,[uint64]0x2345000000000042)
        $merge = $owner.GetType().GetMethod('Merge',[Reflection.BindingFlags]'Instance,NonPublic')
        { $merge.Invoke($owner,[object[]]@($extension)) } | Should -Throw
    }
    It 'reconstructs long-name links and DOS completeness counts from an extension record' {
        $owner = Read-Record (New-FileRecord -OwnerWithoutNames)
        $extension = Read-Record (New-FileRecord -ExtensionOnlyNames)
        $owner.GetType().GetMethod('Merge',[Reflection.BindingFlags]'Instance,NonPublic').Invoke($owner,[object[]]@($extension))
        (Field $owner NameAttributeCount) | Should -Be (Field $owner LinkCount)
        @(Field $owner Links).Count | Should -Be 2
        (Field $owner Length) | Should -Be 5
        (Field $owner HasStandardInformation) | Should -BeTrue
    }
    It 'distinguishes fatal traversal aborts from recoverable inventory errors' {
        $summary = [FileInspectorX.Prototypes.FileSystem.InventorySummary]::new()
        $summary.AddError()
        $summary.Aborted | Should -BeFalse
        $summary.AddError($true)
        $summary.AddError()
        $summary.Aborted | Should -BeTrue
        $summary.Errors | Should -Be 3
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
