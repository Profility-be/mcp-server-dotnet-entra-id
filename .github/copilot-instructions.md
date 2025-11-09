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


## Belangrijke Code Locaties

### OAuth Endpoints
- **POST /oauth/register** - Dynamic client registration (RFC 7591)
- **GET/POST /oauth/authorize** - Authorization endpoint (toont login UI)
- **POST /oauth/continue** - User bevestigt login → redirect naar Entra ID
- **POST /oauth/cancel** - User annuleert login
- **GET /oauth/callback** - Entra ID callback na authenticatie
- **POST /oauth/token** - Token exchange endpoint

### MCP Tool Voorbeeld
- **WhoAmITool.cs** - Demonstreert hoe user claims te lezen uit JWT token
- Toont: naam, email, UPN, Object ID, tenant ID
