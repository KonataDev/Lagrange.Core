using Lagrange.Core.Utility.Binary;
using Lagrange.Core.Utility.Binary.Tlv;
using Lagrange.Core.Utility.Binary.Tlv.Attributes;

namespace Lagrange.Core.Internal.Packets.Tlv;

[Tlv(0x17E, true)]
internal class Tlv17E : TlvBody
{
    // ������һ̨���豸��¼QQ������������֤
    [BinaryProperty] public string tip { get; set; }
}