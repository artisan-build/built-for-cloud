<style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; background: #f4f1ea; color: #17251f; }
    body { margin: 0; }
    .bfc-auth { width: min(42rem, calc(100% - 2rem)); margin: 4rem auto; }
    .bfc-panel { background: #fffdf8; border: 1px solid #d8d2c5; border-radius: 1rem; padding: clamp(1.25rem, 4vw, 2.5rem); box-shadow: 0 1.5rem 4rem rgba(44, 53, 47, .08); }
    .bfc-kicker { color: #a54824; font-size: .75rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
    .bfc-auth h1 { margin: .5rem 0 1.5rem; font-family: ui-serif, Georgia, serif; font-size: clamp(2rem, 8vw, 3.25rem); line-height: .98; }
    .bfc-auth label { display: grid; gap: .4rem; margin: 1rem 0; font-weight: 700; }
    .bfc-auth input, .bfc-auth select { box-sizing: border-box; width: 100%; border: 1px solid #aaa497; border-radius: .5rem; padding: .75rem; background: white; font: inherit; }
    .bfc-auth button, .bfc-button { display: inline-block; border: 0; border-radius: 999px; padding: .7rem 1.1rem; background: #173f35; color: white; font: inherit; font-weight: 800; text-decoration: none; cursor: pointer; }
    .bfc-link { color: #173f35; font-weight: 700; }
    .bfc-error { color: #9b2f1a; }
    .bfc-status { border-left: .25rem solid #28735e; padding: .75rem 1rem; background: #e7f2ec; }
    .bfc-list { display: grid; gap: .75rem; padding: 0; list-style: none; }
    .bfc-row { border-top: 1px solid #ddd6c8; padding-top: 1rem; }
    .bfc-actions { display: flex; flex-wrap: wrap; align-items: end; gap: .75rem; }
    .bfc-actions form { flex: 1 1 12rem; }
    @media (max-width: 36rem) { .bfc-auth { margin: 1rem auto; } .bfc-panel { border-radius: .65rem; } }
</style>
