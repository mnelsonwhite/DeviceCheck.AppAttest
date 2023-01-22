using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Diagnostics.CodeAnalysis;

namespace DeviceCheck.AppAttest.Cbor.CodeGeneration;

static class SyntaxNodeExtensions
{
    public static bool TryGetParent<T>(
        this SyntaxNode node,
        [NotNullWhen(returnValue: true)] out T? parent
    ) where T: SyntaxNode
    {
        var nparent = node.Parent;
        while (nparent is not null)
        {
            if (nparent is T t) {
                parent = t;
                return true;
            }

            nparent = nparent.Parent;
        }

        parent = default;
        return false;
    }

    public static bool TryGetNamespaceName(
        this SyntaxNode node,
        [NotNullWhen(returnValue:true)] out string? namespaceName)
    {
        if(node.TryGetParent<NamespaceDeclarationSyntax>(out var namespaceSyntax))
        {
            namespaceName = namespaceSyntax.Name.ToString();
            return true;
        }

        if(node.TryGetParent<FileScopedNamespaceDeclarationSyntax>(out var fileScopedNamespaceSyntax))
        {
            namespaceName = fileScopedNamespaceSyntax.Name.ToString();
            return true;
        }

        namespaceName = default;
        return false;
    }
}