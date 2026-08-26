# AI Assistant Instructions - MCP Server met .NET en Microsoft Entra ID

## Doel van dit Project

Dit project is een **OAuth 2.1 proxy** die Claude AI verbindt met Microsoft Entra ID voor authenticatie van Model Context Protocol (MCP) servers. Het lost het probleem op dat Claude RFC 7591 Dynamic Client Registration vereist, terwijl Entra ID dit niet ondersteunt.

## Belangrijkste Contextbestanden

Voor volledig begrip van dit project, lees de volgende documentatie:

1. **[README.md](../README.md)** - Bevat:
   - Project overzicht en features
   - Setup instructies (Azure AD app registratie, configuratie)
   - Deployment stappen
   - Gebruik met Claude AI
   - Screenshots en voorbeelden

2. **[README-Architecture.md](../README-Architecture.md)** - Bevat:
   - Technische architectuur en flows
   - OAuth 2.1 proxy design
   - PKCE implementatie details
   - Token mapping strategie
   - Security considerations
   - Production deployment aanbevelingen
   - Database schema's voor persistente storage

3. **[UPGRADING.md](../UPGRADING.md)** - Bevat:
   - Migratie van .NET 8 + MCP C# SDK 0.4.0-preview.2 naar .NET 10 + SDK 2.2.0
   - Welk gedrag wijzigde (tool naming, stateless transport, protected resource metadata)
   - Hoe het oude gedrag terug aan te zetten via `MCP:SessionMode` / `MCP:EnableLegacySse`

## Technische Uitgangspunten

Dit project is een template: de code moet tonen hoe je het vandaag hoort te doen. Houd je aan de
volgende patronen bij wijzigingen:

- **Target framework**: `net10.0`. MCP C# SDK: `2.2.0` (stable, geen preview).
- **Lees de gebruiker in een tool via `RequestContext<CallToolRequestParams>.User`**, niet via
  `IHttpContextAccessor`. Die laatste is niet betrouwbaar in een stateful sessie.
- **Streamable HTTP is stateless by default** (`MCP:SessionMode`). Ga er niet van uit dat `/sse`
  bestaat, en niet dat sampling/elicitation/roots beschikbaar zijn.
- **Tools declareren annotaties** (`Title`, `ReadOnly`, `Idempotent`, `OpenWorld`). Die zijn goedkoop
  en komen wel door.
- **Houd voorbeeldtools simpel.** Structured output (een getypeerd record, `UseStructuredContent`)
  is geprobeerd en teruggedraaid: de SDK publiceert dan wel een `outputSchema` met
  veld-descriptions, maar noch Claude AI noch Claude Code doet er vandaag iets mee. Zelfde voor
  `notifications/progress`: correct verstuurd, nergens weergegeven. Voeg zulke dingen niet toe
  "omdat het kan" - alleen als een client ze aantoonbaar gebruikt.
- **Wat het model ziet is `[Description]` op de methode, niet XML-docs.** `///`-commentaar komt niet
  in het gepubliceerde schema terecht. Gebruik XML-docs voor ontwikkelaars.
- **RFC 9728 protected resource metadata staat in `Program.cs`** (`McpAuthenticationOptions`), niet in
  `WellKnownController`. Alleen de authorization-server metadata (RFC 8414) is handgeschreven.
- **Backwards compatibiliteit**: hernoem geen bestaande configuratiesleutels en wijzig geen
  signatures van `IClaimProvider`, `ITokenStore`, `ILoginTokenStore`, `IClientStore`, `IJwtBuilder`
  of `IBrandingProvider` - clones hangen daaraan. Voeg toe in plaats van te herbenoemen, en
  documenteer elke gedragswijziging in UPGRADING.md.

## Belangrijke Code Locaties

### OAuth Endpoints
- **POST /oauth/register** - Dynamic client registration (RFC 7591)
- **GET/POST /oauth/authorize** - Authorization endpoint (toont login UI)
- **POST /oauth/continue** - User bevestigt login → redirect naar Entra ID
- **POST /oauth/cancel** - User annuleert login
- **GET /oauth/callback** - Entra ID callback na authenticatie
- **POST /oauth/token** - Token exchange endpoint

### MCP Tool Voorbeeld
- **WhoAmITool.cs** - Demonstreert hoe user claims te lezen uit het JWT token
- Wire name: `who_am_i` (lower snake_case van de methodenaam)
- Toont: naam, email, UPN, Object ID en de allowlisted claims, als leesbare tekst
