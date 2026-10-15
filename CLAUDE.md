# bastion-client

Package npm pubblico `@heyatom/bastion-client`: SDK per Bastion (core, adapter NestJS, webhook).
Come è fatto e perché: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Comandi

```bash
pnpm lint      # tsc --noEmit
pnpm test      # vitest
pnpm build     # tsc CJS + ESM in dist/
pnpm test:di   # avvia BastionModule da dist/cjs (dopo build)
```

## Regole

- `README.md` e `CHANGELOG.md` finiscono su npm: in inglese, solo uso del package. Niente path
  interni, nomi di servizi della piattaforma, riferimenti a `api.md` o a piani. Il dettaglio
  tecnico va in `docs/ARCHITECTURE.md`.
- Build solo con `tsc`: un bundler perde `design:paramtypes` e rompe la DI dei consumer.
- Niente dipendenze runtime ESM-only: la build CJS deve restare caricabile da Jest.
- Il core non importa Nest; `src/nest/` riesporta il core.
- Cambia il contratto (API pubblica, errori, header)? Aggiorna anche la guida di piattaforma
  [`../docs/integrations/bastion.md`](../docs/integrations/bastion.md) e il `CHANGELOG.md`.

## Release

`version` in `package.json` + voce in `CHANGELOG.md`, commit, tag `vX.Y.Z`, push del tag: il
workflow `publish.yml` pubblica (trusted publishing). Push e tag solo su richiesta esplicita.
