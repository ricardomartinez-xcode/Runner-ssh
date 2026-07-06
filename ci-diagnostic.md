# CI diagnosis

npm install: 0
npm run check: 2
npm test: 0

## npm install

added 54 packages, and audited 55 packages in 9s

15 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities

## npm run check

> runner-ssh@0.1.0 check
> tsc --noEmit -p tsconfig.json

src/app.ts(1,46): error TS2307: Cannot find module 'fastify' or its corresponding type declarations.
src/app.ts(2,29): error TS2307: Cannot find module 'zod' or its corresponding type declarations.
src/app.ts(10,16): error TS2664: Invalid module name in augmentation, module 'fastify' cannot be found.
src/app.ts(51,27): error TS7006: Parameter 'error' implicitly has an 'any' type.
src/app.ts(51,34): error TS7006: Parameter '_request' implicitly has an 'any' type.
src/app.ts(51,44): error TS7006: Parameter 'reply' implicitly has an 'any' type.
src/app.ts(60,38): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(65,40): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(66,54): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(67,36): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(68,46): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(70,39): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(70,48): error TS7006: Parameter 'reply' implicitly has an 'any' type.
src/app.ts(74,49): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(75,40): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(80,44): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/app.ts(84,48): error TS7006: Parameter 'request' implicitly has an 'any' type.
src/auth.ts(1,64): error TS2307: Cannot find module 'jose' or its corresponding type declarations.
src/auth.ts(2,15): error TS2305: Module '"./config.js"' has no exported member 'Environm'.
src/auth.ts(32,37): error TS2304: Cannot find name 'Environment'.
src/config.ts(2,18): error TS2307: Cannot find module 'yaml' or its corresponding type declarations.
src/config.ts(3,19): error TS2307: Cannot find module 'zod' or its corresponding type declarations.
src/config.ts(48,45): error TS7006: Parameter 'value' implicitly has an 'any' type.
src/config.ts(49,68): error TS7006: Parameter 'value' implicitly has an 'any' type.
src/config.ts(78,32): error TS18046: 'target' is of type 'unknown'.

## npm test

> runner-ssh@0.1.0 test
> vitest run


[1m[46m RUN [49m[22m [36mv3.2.7 [39m[90m/home/runner/work/Runner-ssh/Runner-ssh[39m

 [32m✓[39m tests/redaction.test.ts [2m([22m[2m1 test[22m[2m)[22m[32m 3[2mms[22m[39m
 [32m✓[39m tests/registry.test.ts [2m([22m[2m2 tests[22m[2m)[22m[32m 4[2mms[22m[39m

[2m Test Files [22m [1m[32m2 passed[39m[22m[90m (2)[39m
[2m      Tests [22m [1m[32m3 passed[39m[22m[90m (3)[39m
[2m   Start at [22m 15:04:58
[2m   Duration [22m 374ms[2m (transform 104ms, setup 0ms, collect 113ms, tests 7ms, environment 1ms, prepare 199ms)[22m

