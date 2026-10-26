# Deployment and rollback

The existing Vercel `openconsole` project is linked to this repository. Pull
requests and non-main branches receive protected previews. `main` is production
and uses production Convex URLs stored in Vercel; previews use preview/development
configuration. No provider credential belongs in Git.

Before accepting production, inspect its repository/commit metadata and run
health, documentation endpoints, accessibility, catalog, upload/analyzer, and
download/digest tests. Roll back with `vercel rollback <accepted-deployment>` or
promote the preceding accepted deployment. Never rebuild a different commit and
call it the tested artifact.
