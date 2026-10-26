# OpenConsole catalog

Public Next.js and Convex source for the OpenConsole game catalog and versioned
developer documentation.

- Production: https://openconsole-araujota97gmailcoms-projects.vercel.app
- Runtime: https://github.com/araujota/openconsole
- Documentation: https://openconsole-araujota97gmailcoms-projects.vercel.app/docs
- Compatible runtime: `v0.1.0-ovmf-preview.1`

```sh
npm ci
cp .env.example .env.local
npm run validate:docs
npm run lint
npm run typecheck
npm run test:unit
npm run build
npm run test:e2e
```

The production catalog is public. Publication remains reviewer-only; accepted
analysis is not a sandbox or proof of safety. Never commit Convex/Vercel
credentials or generated `.env`/`.vercel` state.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
