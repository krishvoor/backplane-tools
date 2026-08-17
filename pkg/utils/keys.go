package utils

// RedHatReleaseKey2ArmoredPublicKey is the armored OpenPGP public key for
// "Red Hat, Inc. (release key 2) <security@redhat.com>", pinned directly in
// source rather than fetched at runtime.
//
// mirror.openshift.com serves both the tool artifacts (e.g. the 'oc' client
// tarball) and their checksums/signatures over the same HTTPS connection. An
// attacker positioned on the network path (or a compromised/malicious proxy)
// could tamper with the tarball and its plaintext sha256sum.txt in transit,
// since both are protected only by that single transport channel. Pinning
// this key lets us cryptographically verify the detached-signed checksum
// file (sha256sum.txt.gpg) against a trust anchor that does not depend on
// the same transport used to fetch the artifacts, so integrity no longer
// relies solely on TLS.
//
// Fingerprint: 567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51
// Key ID:      199E2F91FD431D51
// Source:      https://access.redhat.com/security/team/key
//
//	https://security.access.redhat.com/data/fd431d51.txt
const RedHatReleaseKey2ArmoredPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.22 (GNU/Linux)

mQINBErgSTsBEACh2A4b0O9t+vzC9VrVtL1AKvUWi9OPCjkvR7Xd8DtJxeeMZ5eF
0HtzIG58qDRybwUe89FZprB1ffuUKzdE+HcL3FbNWSSOXVjZIersdXyH3NvnLLLF
0DNRB2ix3bXG9Rh/RXpFsNxDp2CEMdUvbYCzE79K1EnUTVh1L0Of023FtPSZXX0c
u7Pb5DI5lX5YeoXO6RoodrIGYJsVBQWnrWw4xNTconUfNPk0EGZtEnzvH2zyPoJh
XGF+Ncu9XwbalnYde10OCvSWAZ5zTCpoLMTvQjWpbCdWXJzCm6G+/hx9upke546H
5IjtYm4dTIVTnc3wvDiODgBKRzOl9rEOCIgOuGtDxRxcQkjrC+xvg5Vkqn7vBUyW
9pHedOU+PoF3DGOM+dqv+eNKBvh9YF9ugFAQBkcG7viZgvGEMGGUpzNgN7XnS1gj
/DPo9mZESOYnKceve2tIC87p2hqjrxOHuI7fkZYeNIcAoa83rBltFXaBDYhWAKS1
PcXS1/7JzP0ky7d0L6Xbu/If5kqWQpKwUInXtySRkuraVfuK3Bpa+X1XecWi24JY
HVtlNX025xx1ewVzGNCTlWn1skQN2OOoQTV4C8/qFpTW6DTWYurd4+fE0OJFJZQF
buhfXYwmRlVOgN5i77NTIJZJQfYFj38c/Iv5vZBPokO6mffrOTv3MHWVgQARAQAB
tDNSZWQgSGF0LCBJbmMuIChyZWxlYXNlIGtleSAyKSA8c2VjdXJpdHlAcmVkaGF0
LmNvbT6JAjYEEwEIACACGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAUCSuBJPAAK
CRAZni+R/UMdUfIkD/9m3HWv07uJG26R3KBexTo2FFu3rmZs+m2nfW8R3dBX+k0o
AOFpgJCsNgKwU81LOPrkMN19G0+Yn/ZTCDD7cIQ7dhYuDyEX97xh4une/EhnnRuh
ASzR+1xYbj/HcYZIL9kbslgpebMn+AhxbUTQF/mziug3hLidR9Bzvygq0Q09E11c
OZL4BU6J2HqxL+9m2F+tnLdfhL7MsAq9nbmWAOpkbGefc5SXBSq0sWfwoes3X3yD
Q8B5Xqr9AxABU7oUB+wRqvY69ZCxi/BhuuJCUxY89ZmwXfkVxeHl1tYfROUwOnJO
GYSbI/o41KBK4DkIiDcT7QqvqvCyudnxZdBjL2QU6OrIJvWmKs319qSF9m3mXRSt
ZzWtB89Pj5LZ6cdtuHvW9GO4qSoBLmAfB313pGkbgi1DE6tqCLHlA0yQ8zv99OWV
cMDGmS7tVTZqfX1xQJ0N3bNORQNtikJC3G+zBCJzIeZleeDlMDQcww00yWU1oE7/
To2UmykMGc7o9iggFWR2g0PIcKsA/SXdRKWPqCHG2uKHBvdRTQGupdXQ1sbV+AHw
ycyA/9H/mp/NUSNM2cqnBDcZ6GhlHt59zWtEveiuU5fpTbp4GVcFXbW8jStj8j8z
1HI3cywZO8+YNPzqyx0JWsidXGkfzkPHyS4jTG84lfu2JG8m/nqLnRSeKpl20Q==
=79bX
-----END PGP PUBLIC KEY BLOCK-----
`
