using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

if (args.Length != 1 || File.Exists(args[0]))
    throw new ArgumentException("usage: Winmd NEW_OUTPUT.winmd");

var metadata = new MetadataBuilder();
var code = new BlobBuilder();
var windowsRuntime = (AssemblyFlags)0x200;
metadata.AddModule(0, metadata.GetOrAddString("Wvb.Test.winmd"),
    metadata.GetOrAddGuid(new Guid("52B36210-1F59-4F9D-A815-97018507F126")), default, default);
metadata.AddAssembly(metadata.GetOrAddString("Wvb.Test"), new Version(1, 0, 0, 0),
    default, default, windowsRuntime, AssemblyHashAlgorithm.None);
var core = metadata.AddAssemblyReference(metadata.GetOrAddString("mscorlib"),
    new Version(4, 0, 0, 0), default,
    metadata.GetOrAddBlob(Convert.FromHexString("B77A5C561934E089")), default, default);
var windows = metadata.AddAssemblyReference(metadata.GetOrAddString("Windows"),
    new Version(255, 255, 255, 255), default, default, windowsRuntime, default);
TypeReferenceHandle Type(EntityHandle scope, string ns, string name) =>
    metadata.AddTypeReference(scope, metadata.GetOrAddString(ns), metadata.GetOrAddString(name));
var systemObject = Type(core, "System", "Object");
var systemType = Type(core, "System", "Type");
var guidType = Type(windows, "Windows.Foundation.Metadata", "GuidAttribute");
var activatableType = Type(windows, "Windows.Foundation.Metadata", "ActivatableAttribute");
var defaultType = Type(windows, "Windows.Foundation.Metadata", "DefaultAttribute");

MemberReferenceHandle Constructor(EntityHandle parent, int count,
    Action<ParametersEncoder> parameters)
{
    var blob = new BlobBuilder();
    new BlobEncoder(blob).MethodSignature(isInstanceMethod: true)
        .Parameters(count, result => result.Void(), parameters);
    return metadata.AddMemberReference(parent, metadata.GetOrAddString(".ctor"),
        metadata.GetOrAddBlob(blob));
}
var guidConstructor = Constructor(guidType, 11, parameters => {
    parameters.AddParameter().Type().UInt32();
    parameters.AddParameter().Type().UInt16();
    parameters.AddParameter().Type().UInt16();
    for (int i = 0; i < 8; ++i) parameters.AddParameter().Type().Byte();
});
var activatableConstructor = Constructor(activatableType, 2, parameters => {
    parameters.AddParameter().Type().Type(systemType, false);
    parameters.AddParameter().Type().UInt32();
});
var defaultConstructor = Constructor(defaultType, 0, _ => {});
void GuidAttribute(EntityHandle parent, string value)
{
    var blob = new BlobBuilder();
    blob.WriteUInt16(1);
    blob.WriteBytes(new Guid(value).ToByteArray());
    blob.WriteUInt16(0);
    metadata.AddCustomAttribute(parent, guidConstructor, metadata.GetOrAddBlob(blob));
}

metadata.AddTypeDefinition(TypeAttributes.NotPublic, default, metadata.GetOrAddString("<Module>"),
    default, MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
var flags = TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract |
    TypeAttributes.WindowsRuntime;
var factory = metadata.AddTypeDefinition(flags, metadata.GetOrAddString("Wvb.Test"),
    metadata.GetOrAddString("IWvbScalarFactory"), default,
    MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
var instance = metadata.AddTypeDefinition(flags, metadata.GetOrAddString("Wvb.Test"),
    metadata.GetOrAddString("IWvbScalarInstance"), default,
    MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(3));
var runtimeClass = metadata.AddTypeDefinition(
    TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.WindowsRuntime,
    metadata.GetOrAddString("Wvb.Test"), metadata.GetOrAddString("WvbScalarRuntimeClass"),
    systemObject, MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(6));
GuidAttribute(factory, "5F1C7A3E-2B4D-4E6F-8A9B-0C1D2E3F4A51");
GuidAttribute(instance, "5F1C7A3E-2B4D-4E6F-8A9B-0C1D2E3F4A52");
var implementation = metadata.AddInterfaceImplementation(runtimeClass, instance);
var emptyAttribute = new BlobBuilder();
emptyAttribute.WriteUInt16(1);
emptyAttribute.WriteUInt16(0);
metadata.AddCustomAttribute(implementation, defaultConstructor, metadata.GetOrAddBlob(emptyAttribute));
var activatable = new BlobBuilder();
activatable.WriteUInt16(1);
activatable.WriteSerializedString("Wvb.Test.IWvbScalarFactory");
activatable.WriteUInt32(1);
activatable.WriteUInt16(0);
metadata.AddCustomAttribute(runtimeClass, activatableConstructor, metadata.GetOrAddBlob(activatable));

void Method(string name, Action<ReturnTypeEncoder> result, bool input)
{
    var blob = new BlobBuilder();
    new BlobEncoder(blob).MethodSignature(isInstanceMethod: true)
        .Parameters(input ? 1 : 0, result, parameters => {
            if (input) parameters.AddParameter().Type().UInt32();
        });
    var parameter = MetadataTokens.ParameterHandle(1);
    metadata.AddMethodDefinition(MethodAttributes.Public | MethodAttributes.Virtual |
        MethodAttributes.Abstract | MethodAttributes.NewSlot | MethodAttributes.HideBySig,
        MethodImplAttributes.Runtime, metadata.GetOrAddString(name),
        metadata.GetOrAddBlob(blob), -1, parameter);
}
// IInspectable supplies slots 0..5; these real declarations account for the gaps.
Method("ReservedFactory", result => result.Void(), false);
Method("Create", result => result.Type().Type(runtimeClass, false), false);
Method("Reserved0", result => result.Void(), false);
Method("Reserved1", result => result.Void(), false);
Method("Transform", result => result.Type().UInt32(), true);
metadata.AddParameter(ParameterAttributes.In, metadata.GetOrAddString("input"), 1);

var builder = new ManagedPEBuilder(
    new PEHeaderBuilder(machine: Machine.Amd64,
        imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
    new MetadataRootBuilder(metadata, "WindowsRuntime 1.4"), code,
    flags: CorFlags.ILOnly,
    deterministicIdProvider: _ => new BlobContentId(
        new Guid("52B36210-1F59-4F9D-A815-97018507F126"), 0));
var pe = new BlobBuilder();
builder.Serialize(pe);
using (var output = new FileStream(args[0], FileMode.CreateNew)) pe.WriteContentTo(output);

using var stream = File.OpenRead(args[0]);
using var reader = new PEReader(stream);
var md = reader.GetMetadataReader(MetadataReaderOptions.None);
if (reader.PEHeaders.CoffHeader.Machine != Machine.Amd64 ||
    md.MetadataVersion != "WindowsRuntime 1.4" ||
    (md.GetAssemblyDefinition().Flags & windowsRuntime) == 0 ||
    md.MethodDefinitions.Count != 5 || md.TypeDefinitions.Count != 4)
    throw new InvalidDataException("emitted WinMD header/table validation failed");
foreach (var handle in new[] { factory, instance, runtimeClass })
    if ((md.GetTypeDefinition(handle).Attributes & TypeAttributes.WindowsRuntime) == 0)
        throw new InvalidDataException("missing WindowsRuntime type flag");
foreach (var handle in md.MethodDefinitions)
    if (md.GetMethodDefinition(handle).RelativeVirtualAddress != 0)
        throw new InvalidDataException("WinMD abstract method unexpectedly has a body");
if (!md.GetTypeDefinition(factory).GetMethods().Select(handle =>
        md.GetString(md.GetMethodDefinition(handle).Name)).SequenceEqual(new[] {"ReservedFactory", "Create"}) ||
    !md.GetTypeDefinition(instance).GetMethods().Select(handle =>
        md.GetString(md.GetMethodDefinition(handle).Name)).SequenceEqual(new[] {"Reserved0", "Reserved1", "Transform"}))
    throw new InvalidDataException("WinMD interface method ordering/slot validation failed");
Console.WriteLine("winmd: WindowsRuntime 1.4; AMD64; factory slot7; instance slot8; metadata tables verified");
