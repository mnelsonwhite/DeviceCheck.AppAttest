using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DeviceCheck.AppAttest.Cbor.CodeGeneration;

class SyntaxReceiver : ISyntaxReceiver
{
    public void OnVisitSyntaxNode(SyntaxNode syntaxNode)
    {
        if (!syntaxNode.TryGetNamespaceName(out var namespaceName)
            || !syntaxNode.TryGetParent<ClassDeclarationSyntax>(out var classSyntax)
            || !classSyntax.Modifiers.Any(v => v is SyntaxToken st && st.Text == "partial"))
        {
            return;
        }

        var className = classSyntax.Identifier.Text;
        var fullClassName = $"{namespaceName}.{className}";

        if (syntaxNode is AttributeSyntax {
                Name: IdentifierNameSyntax { Identifier.Text: "CborMap"}
            } mapAttr
        ) {
            var keyType = (mapAttr.ArgumentList?.Arguments.FirstOrDefault()?.Expression as LiteralExpressionSyntax)?.Token.ValueText
                ?? "typeof(string)";

            var modifiers = String.Join(" ", classSyntax.Modifiers.Select(v => v.Text));
            Classes.Add(new TargetClass(className, namespaceName, keyType, modifiers));
        }

        if (syntaxNode is AttributeSyntax {
                Name: IdentifierNameSyntax { Identifier.Text: "CborProperty" }
            } propAttr
            && propAttr.TryGetParent<PropertyDeclarationSyntax>(out var propSyntax)
        ) {
            if (!Props.ContainsKey(fullClassName))
            {
                Props[fullClassName] = new List<TargetProp>();
            }

            var keyValue = (propAttr.ArgumentList?.Arguments.FirstOrDefault()?.Expression as LiteralExpressionSyntax)?.Token.ToString()
            ?? $"\"{propSyntax.Identifier.Text}\"";

            var typeValue = propSyntax.Type is NullableTypeSyntax nt ? nt.ElementType.ToString() : propSyntax.Type.ToString();

            Props[fullClassName].Add(new TargetProp(
                keyValue,
                typeValue,
                propSyntax.Identifier.Text
            ));
        }
    }

    public record TargetClass(string className, string namespaceName, string keyType, string modifiers);
    public record TargetProp(string keyValue, string propertyType, string propertyName);
    public readonly List<TargetClass> Classes = new List<TargetClass>();
    public readonly Dictionary<string, List<TargetProp>> Props = new Dictionary<string, List<TargetProp>>();
}
