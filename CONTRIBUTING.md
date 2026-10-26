# Contributing

Use Node 22.14 or newer. Run `npm ci`, documentation validation, lint,
typecheck, unit tests, production build, and Playwright before opening a pull
request. Keep public function validators explicit, use Convex indexes rather
than table scans, and preserve reviewer-only publication.

Pull requests deploy to protected Vercel previews. `main` is the production
branch. Never commit `.env*`, `.vercel`, provider tokens, storage exports, or
browser authentication state. Runtime/format changes belong in
https://github.com/araujota/openconsole.
