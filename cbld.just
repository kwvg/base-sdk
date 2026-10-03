# Cargo debug builds, one recipe per workspace crate.

[doc('Build dash-dev')]
dev:
    cargo build -p dash-dev --features full

[doc('Build dash-num')]
num:
    cargo build -p dash-num --features full

[doc('Build dash-p2p-core')]
p2p_core:
    cargo build -p dash-p2p-core --features full

[doc('Build dash-params')]
params:
    cargo build -p dash-params --features full

[doc('Build dash-pkc')]
pkc:
    cargo build -p dash-pkc --features full

[doc('Build dash-pow')]
pow:
    cargo build -p dash-pow --features full

[doc('Build dash-primitives')]
primitives:
    cargo build -p dash-primitives --features full

[doc('Build dash-script')]
script:
    cargo build -p dash-script --features full

[doc('Build dash-types')]
types:
    cargo build -p dash-types --features full
