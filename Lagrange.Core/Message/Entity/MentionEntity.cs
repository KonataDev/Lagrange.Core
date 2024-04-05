using Lagrange.Core.Internal.Packets.Message.Element;
using Lagrange.Core.Internal.Packets.Message.Element.Implementation;
using Lagrange.Core.Internal.Packets.Message.Element.Implementation.Extra;
using Lagrange.Core.Utility.Extension;
using ProtoBuf;
using BitConverter = Lagrange.Core.Utility.Binary.BitConverter;

namespace Lagrange.Core.Message.Entity;

[MessageElement(typeof(Text))]
public class MentionEntity : IMessageEntity
{
    public uint Uin { get; set; }
    
    public string Uid { get; set; }
    
    public string? Name { get; set; }
    
    public MentionEntity()
    {
        Uin = 0;
        Uid = "";
        Name = "";
    }
    
    /// <summary>
    /// Set target to 0 to mention everyone
    /// </summary>
    public MentionEntity(string? name, uint target = 0)
    {
        Uin = target;
        Uid = ""; // automatically resolved by MessagingLogic.cs
        Name = name;
    }

    IEnumerable<Elem> IMessageEntity.PackElement()
    {
        var reserve = new MentionExtra
        {
            Type = Uin == 0 ? 1 : 2,
            Uin = 0,
            Field5 = 0,
            Uid = Uid,
        };
        using var stream = new MemoryStream();
        Serializer.Serialize(stream, reserve);
        
        return new Elem[]
        {
            new()
            {
                Text = new Text
                {
                    Str = Name,
                    PbReserve = stream.ToArray()
                }
            }
        };
    }
    
    IMessageEntity? IMessageEntity.UnpackElement(Elem elems)
    {
        if (elems.Text is { Str: not null, PbReserve: { } reserve } && 
            Serializer.Deserialize<MentionExtra>(reserve.AsSpan()) is { } extra and ({ Type: 2, Uin: not 0 } or { Type: 1 }))
        {
            return new MentionEntity
            {
                Uin = extra.Uin ?? 0,
                Uid = extra.Uid ?? "",
                Name = elems.Text.Str
            };
        }
        
        return null;
    }

    public string ToPreviewString()
    {
        return $"[Mention]: {Name}({Uin})";
    }

    public string ToPreviewText() => $"{Name} ";
}