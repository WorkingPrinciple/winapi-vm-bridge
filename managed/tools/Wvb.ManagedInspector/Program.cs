using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Wvb.ManagedInspector;

internal static class Program
{
    private const uint RequestSchemaBase = 0x3000_0000;

    private static int Main(string[] args)
    {
        try
        {
            Options options = Options.Parse(args);
            JsonObject contract = Inspect(options);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(options.Output))!);
            File.WriteAllText(
                options.Output,
                contract.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"wvb-managed-inspect: {error.Message}");
            return 2;
        }
    }

    private static JsonObject Inspect(Options options)
    {
        ValidateQualifiedIdentifier(options.AdapterId, requireDot: true);
        ValidateRelativePath(options.RelativePath);
        byte[] assemblyBytes = File.ReadAllBytes(options.Assembly);
        using MemoryStream stream = new(assemblyBytes, writable: false);
        using PEReader pe = new(stream);
        if (!pe.HasMetadata)
            throw new InvalidDataException("target is not a managed assembly");

        string architecture = pe.PEHeaders.CoffHeader.Machine switch
        {
            Machine.Amd64 => "x86-64",
            _ => throw new NotSupportedException(
                $"managed scalar inspection is proven only for x86-64, not {pe.PEHeaders.CoffHeader.Machine}")
        };
        if (!pe.PEHeaders.IsDll)
            throw new NotSupportedException(".NET EXE inspection is outside the managed assembly slice");

        MetadataReader metadata = pe.GetMetadataReader();
        AssemblyDefinition assembly = metadata.GetAssemblyDefinition();
        string assemblyName = metadata.GetString(assembly.Name);
        string assemblyVersion = FormatAssemblyVersion(assembly.Version);
        if ((!assembly.PublicKey.IsNil && metadata.GetBlobBytes(assembly.PublicKey).Length != 0)
            || (pe.PEHeaders.CorHeader?.Flags & CorFlags.StrongNameSigned) != 0)
        {
            throw new NotSupportedException(
                "strong-name identity requires authorized signing and binding proof");
        }

        ValidateTargetFramework(metadata, assembly);
        ValidateAssemblyReferences(metadata);
        List<ManagedMethod> methods = InspectPublicSurface(metadata);
        if (methods.Count == 0)
            throw new NotSupportedException("assembly has no supported public scalar static methods");

        methods.Sort(ManagedMethod.Compare);
        string rootNamespace = CommonNamespace(methods.Select(method => method.Namespace));
        JsonArray operations = new();
        for (int index = 0; index < methods.Count; index++)
            operations.Add(OperationJson(methods[index], checked((uint)index + 1)));

        string adapterVersion =
            $"{assembly.Version.Major}.{assembly.Version.Minor}.{assembly.Version.Build}";
        return new JsonObject
        {
            ["schema_version"] = 2,
            ["adapter_id"] = options.AdapterId,
            ["adapter_version"] = adapterVersion,
            ["family"] = "dot-net-assembly",
            ["target"] = new JsonObject
            {
                ["relative_path"] = options.RelativePath.Replace('\\', '/'),
                ["sha256"] = Convert.ToHexString(SHA256.HashData(assemblyBytes)).ToLowerInvariant(),
                ["architecture"] = architecture
            },
            ["managed"] = new JsonObject
            {
                ["assembly_name"] = assemblyName,
                ["assembly_version"] = assemblyVersion,
                ["root_namespace"] = rootNamespace,
                ["target_framework"] = "net8.0-windows",
                ["requires_strong_name"] = false,
                ["strong_name_key_file"] = null
            },
            ["dependencies"] = new JsonArray(),
            ["types"] = new JsonObject(),
            ["operations"] = operations
        };
    }

    private static List<ManagedMethod> InspectPublicSurface(MetadataReader metadata)
    {
        ScalarTypeProvider provider = new();
        List<ManagedMethod> methods = new();
        foreach (TypeDefinitionHandle handle in metadata.TypeDefinitions)
        {
            TypeDefinition type = metadata.GetTypeDefinition(handle);
            string typeName = metadata.GetString(type.Name);
            TypeAttributes visibility = type.Attributes & TypeAttributes.VisibilityMask;
            if (typeName == "<Module>" || visibility == TypeAttributes.NotPublic)
                continue;
            if (visibility != TypeAttributes.Public)
                throw new NotSupportedException($"{typeName} is a nested public type");

            string typeNamespace = metadata.GetString(type.Namespace);
            string declaringType = string.IsNullOrEmpty(typeNamespace)
                ? typeName
                : $"{typeNamespace}.{typeName}";
            ValidateQualifiedIdentifier(declaringType, requireDot: false);
            if (type.GetGenericParameters().Any())
                throw new NotSupportedException($"{declaringType} is generic");
            if ((type.Attributes & (TypeAttributes.Abstract | TypeAttributes.Sealed))
                != (TypeAttributes.Abstract | TypeAttributes.Sealed))
            {
                throw new NotSupportedException($"{declaringType} is not a static type");
            }

            RejectVisibleFields(metadata, type, declaringType);
            int methodCountBefore = methods.Count;
            foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
            {
                MethodDefinition method = metadata.GetMethodDefinition(methodHandle);
                MethodAttributes access = method.Attributes & MethodAttributes.MemberAccessMask;
                if (access != MethodAttributes.Public)
                    continue;
                string methodName = metadata.GetString(method.Name);
                ValidateIdentifier(methodName);
                if ((method.Attributes & MethodAttributes.SpecialName) != 0)
                    throw new NotSupportedException(
                        $"{declaringType}.{methodName} is a constructor, property/event accessor or special member");
                if ((method.Attributes & MethodAttributes.Static) == 0)
                    throw new NotSupportedException(
                        $"{declaringType}.{methodName} requires instance-state semantics");
                if (method.GetGenericParameters().Any())
                    throw new NotSupportedException($"{declaringType}.{methodName} is generic");

                MethodSignature<string> signature =
                    method.DecodeSignature(provider, genericContext: null);
                EnsureScalar(signature.ReturnType, $"{declaringType}.{methodName} return");
                List<Parameter> parameterRows = method.GetParameters()
                    .Select(metadata.GetParameter)
                    .Where(parameter => parameter.SequenceNumber != 0)
                    .OrderBy(parameter => parameter.SequenceNumber)
                    .ToList();
                if (parameterRows.Count != signature.ParameterTypes.Length)
                    throw new InvalidDataException(
                        $"{declaringType}.{methodName} has incomplete parameter metadata");
                List<ManagedParameter> parameters = new();
                for (int index = 0; index < parameterRows.Count; index++)
                {
                    string parameterName = metadata.GetString(parameterRows[index].Name);
                    if (string.IsNullOrEmpty(parameterName))
                        throw new NotSupportedException(
                            $"{declaringType}.{methodName} parameter {index + 1} has no stable name");
                    ValidateIdentifier(parameterName);
                    string parameterType = signature.ParameterTypes[index];
                    EnsureScalar(parameterType, $"{declaringType}.{methodName}.{parameterName}");
                    parameters.Add(new ManagedParameter(parameterName, parameterType));
                }
                methods.Add(new ManagedMethod(
                    typeNamespace,
                    declaringType,
                    methodName,
                    signature.ReturnType,
                    parameters));
            }
            if (methods.Count == methodCountBefore)
                throw new NotSupportedException(
                    $"{declaringType} has no supported public scalar static methods");
        }
        return methods;
    }

    private static void RejectVisibleFields(
        MetadataReader metadata,
        TypeDefinition type,
        string declaringType)
    {
        foreach (FieldDefinitionHandle handle in type.GetFields())
        {
            FieldDefinition field = metadata.GetFieldDefinition(handle);
            FieldAttributes access = field.Attributes & FieldAttributes.FieldAccessMask;
            if (access is FieldAttributes.Public
                or FieldAttributes.Family
                or FieldAttributes.FamORAssem)
            {
                throw new NotSupportedException(
                    $"{declaringType}.{metadata.GetString(field.Name)} exposes field state");
            }
        }
    }

    private static JsonObject OperationJson(ManagedMethod method, uint id)
    {
        JsonArray parameters = new();
        foreach (ManagedParameter parameter in method.Parameters)
        {
            parameters.Add(new JsonObject
            {
                ["name"] = parameter.Name,
                ["type_id"] = parameter.Type,
                ["direction"] = "in",
                ["sensitivity"] = "public",
                ["max_bytes"] = null
            });
        }
        uint requestSchema = checked(RequestSchemaBase + checked(id * 2 - 1));
        return new JsonObject
        {
            ["id"] = id,
            ["name"] = method.Name,
            ["symbol"] = $"{method.DeclaringType}.{method.Name}",
            ["calling_convention"] = "winapi",
            ["timeout_ms"] = 1000,
            ["request_schema_id"] = requestSchema,
            ["response_schema_id"] = checked(requestSchema + 1),
            ["parameters"] = parameters,
            ["return_type_id"] = method.ReturnType,
            ["managed"] = new JsonObject
            {
                ["declaring_type"] = method.DeclaringType,
                ["declaring_type_is_static"] = true,
                ["member_name"] = method.Name,
                ["is_public"] = true,
                ["is_static"] = true
            }
        };
    }

    private static void ValidateTargetFramework(
        MetadataReader metadata,
        AssemblyDefinition assembly)
    {
        string? framework = null;
        string? platform = null;
        foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
        {
            CustomAttribute attribute = metadata.GetCustomAttribute(handle);
            string? typeName = AttributeTypeName(metadata, attribute.Constructor);
            if (typeName is not (
                "System.Runtime.Versioning.TargetFrameworkAttribute"
                or "System.Runtime.Versioning.TargetPlatformAttribute"))
            {
                continue;
            }
            BlobReader value = metadata.GetBlobReader(attribute.Value);
            if (value.ReadUInt16() != 1)
                throw new InvalidDataException($"invalid {typeName} metadata");
            string? text = value.ReadSerializedString();
            if (typeName.EndsWith("TargetFrameworkAttribute", StringComparison.Ordinal))
                framework = text;
            else
                platform = text;
        }
        if (framework != ".NETCoreApp,Version=v8.0"
            || platform is null
            || !platform.StartsWith("Windows", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException(
                $"only net8.0-windows is proven (framework={framework ?? "missing"}, platform={platform ?? "missing"})");
        }
    }

    private static void ValidateAssemblyReferences(MetadataReader metadata)
    {
        foreach (AssemblyReferenceHandle handle in metadata.AssemblyReferences)
        {
            AssemblyReference reference = metadata.GetAssemblyReference(handle);
            string name = metadata.GetString(reference.Name);
            if (name != "System" && !name.StartsWith("System.", StringComparison.Ordinal))
            {
                throw new NotSupportedException(
                    $"external managed dependency {name} requires dependency placement proof");
            }
        }
    }

    private static string? AttributeTypeName(
        MetadataReader metadata,
        EntityHandle constructor)
    {
        EntityHandle parent = constructor.Kind switch
        {
            HandleKind.MemberReference =>
                metadata.GetMemberReference((MemberReferenceHandle)constructor).Parent,
            HandleKind.MethodDefinition =>
                metadata.GetMethodDefinition((MethodDefinitionHandle)constructor).GetDeclaringType(),
            _ => default
        };
        return parent.Kind switch
        {
            HandleKind.TypeReference => FullName(metadata, metadata.GetTypeReference((TypeReferenceHandle)parent)),
            HandleKind.TypeDefinition => FullName(metadata, metadata.GetTypeDefinition((TypeDefinitionHandle)parent)),
            _ => null
        };
    }

    private static string FullName(MetadataReader metadata, TypeReference type)
    {
        string name = metadata.GetString(type.Name);
        string typeNamespace = metadata.GetString(type.Namespace);
        return string.IsNullOrEmpty(typeNamespace) ? name : $"{typeNamespace}.{name}";
    }

    private static string FullName(MetadataReader metadata, TypeDefinition type)
    {
        string name = metadata.GetString(type.Name);
        string typeNamespace = metadata.GetString(type.Namespace);
        return string.IsNullOrEmpty(typeNamespace) ? name : $"{typeNamespace}.{name}";
    }

    private static string CommonNamespace(IEnumerable<string> values)
    {
        string[][] namespaces = values
            .Distinct(StringComparer.Ordinal)
            .Select(value => value.Split('.', StringSplitOptions.RemoveEmptyEntries))
            .ToArray();
        if (namespaces.Length == 0 || namespaces.Any(parts => parts.Length == 0))
            throw new NotSupportedException("global-namespace managed types are unsupported");
        int length = namespaces.Min(parts => parts.Length);
        int common = 0;
        while (common < length
            && namespaces.All(parts =>
                string.Equals(parts[common], namespaces[0][common], StringComparison.Ordinal)))
        {
            common++;
        }
        if (common == 0)
            throw new NotSupportedException("public managed types do not share a root namespace");
        return string.Join('.', namespaces[0].Take(common));
    }

    private static void EnsureScalar(string type, string location)
    {
        if (type.StartsWith("unsupported:", StringComparison.Ordinal) || type == "void")
            throw new NotSupportedException($"{location} uses unsupported marshalling type {type}");
    }

    private static string FormatAssemblyVersion(Version version) =>
        $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";

    private static void ValidateQualifiedIdentifier(string value, bool requireDot)
    {
        string[] parts = value.Split('.');
        if ((requireDot && parts.Length < 2) || parts.Length == 0)
            throw new NotSupportedException($"invalid managed identifier {value}");
        foreach (string part in parts)
            ValidateIdentifier(part);
    }

    private static void ValidateIdentifier(string value)
    {
        if (value.Length == 0
            || !(char.IsAsciiLetter(value[0]) || value[0] == '_')
            || value.Skip(1).Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character == '_')))
        {
            throw new NotSupportedException($"invalid managed identifier {value}");
        }
    }

    private static void ValidateRelativePath(string value)
    {
        string[] parts = value.Split(new[] { '/', '\\' }, StringSplitOptions.None);
        if (value.Length == 0
            || Path.IsPathRooted(value)
            || parts.Any(part => part.Length == 0 || part is "." or ".."))
        {
            throw new NotSupportedException($"invalid target relative path {value}");
        }
    }

    private sealed record Options(
        string Assembly,
        string AdapterId,
        string RelativePath,
        string Output)
    {
        internal static Options Parse(string[] args)
        {
            Dictionary<string, string> values = new(StringComparer.Ordinal);
            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException(
                        "usage: --assembly PATH --adapter-id ID --relative-path PATH --out PATH");
                values[args[index]] = args[index + 1];
            }
            return new Options(
                Required(values, "--assembly"),
                Required(values, "--adapter-id"),
                Required(values, "--relative-path"),
                Required(values, "--out"));
        }

        private static string Required(Dictionary<string, string> values, string key) =>
            values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException($"missing {key}");
    }

    private sealed record ManagedParameter(string Name, string Type);

    private sealed record ManagedMethod(
        string Namespace,
        string DeclaringType,
        string Name,
        string ReturnType,
        List<ManagedParameter> Parameters)
    {
        internal static int Compare(ManagedMethod left, ManagedMethod right)
        {
            int result = string.CompareOrdinal(left.DeclaringType, right.DeclaringType);
            if (result != 0)
                return result;
            result = string.CompareOrdinal(left.Name, right.Name);
            if (result != 0)
                return result;
            return string.CompareOrdinal(
                string.Join(',', left.Parameters.Select(parameter => parameter.Type)),
                string.Join(',', right.Parameters.Select(parameter => parameter.Type)));
        }
    }

    private sealed class ScalarTypeProvider : ISignatureTypeProvider<string, object?>
    {
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
        {
            PrimitiveTypeCode.Boolean => "bool",
            PrimitiveTypeCode.SByte => "i8",
            PrimitiveTypeCode.Byte => "u8",
            PrimitiveTypeCode.Int16 => "i16",
            PrimitiveTypeCode.UInt16 => "u16",
            PrimitiveTypeCode.Int32 => "i32",
            PrimitiveTypeCode.UInt32 => "u32",
            PrimitiveTypeCode.Int64 => "i64",
            PrimitiveTypeCode.UInt64 => "u64",
            PrimitiveTypeCode.Single => "f32",
            PrimitiveTypeCode.Double => "f64",
            PrimitiveTypeCode.Void => "void",
            _ => Unsupported(typeCode.ToString())
        };

        public string GetArrayType(string elementType, ArrayShape shape) => Unsupported("array");
        public string GetByReferenceType(string elementType) => Unsupported("byref");
        public string GetFunctionPointerType(MethodSignature<string> signature) =>
            Unsupported("function-pointer");
        public string GetGenericInstantiation(
            string genericType,
            System.Collections.Immutable.ImmutableArray<string> typeArguments) =>
            Unsupported("generic");
        public string GetGenericMethodParameter(object? genericContext, int index) =>
            Unsupported("generic-method-parameter");
        public string GetGenericTypeParameter(object? genericContext, int index) =>
            Unsupported("generic-type-parameter");
        public string GetModifiedType(string modifierType, string unmodifiedType, bool isRequired) =>
            Unsupported("modified");
        public string GetPinnedType(string elementType) => Unsupported("pinned");
        public string GetPointerType(string elementType) => Unsupported("pointer");
        public string GetSZArrayType(string elementType) => Unsupported("array");
        public string GetTypeFromDefinition(
            MetadataReader reader,
            TypeDefinitionHandle handle,
            byte rawTypeKind) => Unsupported("named");
        public string GetTypeFromReference(
            MetadataReader reader,
            TypeReferenceHandle handle,
            byte rawTypeKind) => Unsupported("named");
        public string GetTypeFromSpecification(
            MetadataReader reader,
            object? genericContext,
            TypeSpecificationHandle handle,
            byte rawTypeKind) => Unsupported("specified");

        private static string Unsupported(string kind) => $"unsupported:{kind}";
    }
}
