## What and why

<!-- What this changes and the reason. Link the issue or the plan it comes from. -->

## How it was tested

<!-- Commands run and their results. Say what you could not test (a real iPhone, Windows, Touch ID, a live third-party API). -->

## Security considerations

<!-- Required for anything touching crypto, keys, auth, sync or autofill (plans/03-security-model.md). Otherwise write "None". -->

## Checklist

- [ ] Commits are signed off (`git commit -s`), and a human is the author: no AI co-author trailers or "Generated with" lines
- [ ] Behaviour or architecture changes update the `plans/` file and the matching `docs/` page
- [ ] Notable changes add a file in `changelog/`
- [ ] New UI has English and Arabic strings, and follows `brand/README.md`
- [ ] The zero-knowledge model in `plans/03-security-model.md` isn't weakened
- [ ] No ads, trackers or third-party scripts
- [ ] `pnpm build` passes if the website or docs changed
