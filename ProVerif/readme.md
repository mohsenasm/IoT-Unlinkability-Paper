# Usage of ProVerif

Follow the instruction at the [ProVerif website](https://bblanche.gitlabpages.inria.fr/proverif/) for the installation of ProVerif version 2.05.

Then, you can check the models using the following command:
```bash
    proverif file-name.pv
```

See the [ProVerif user manual](https://bblanche.gitlabpages.inria.fr/proverif/manual.pdf) for more information.

## Unlinkability of multiple publishments

File `unlinkability-of-multiple-publishments.pv`

+ A device publishes multiple events.
+ Multiple devices publish multiple events.

## Unlinkability within one publishment (1)

File `unlinkability-within-one-publishment-1.pv` (with no `knowledge` exposed)

+ Multiple devices follow the protocol and publishes $E_{i}^{(j)}$ using three servers.
+ Multiple sets of three devices partially publish events while the first device only publishes $E_{i}^{(1)}$, the second device only publishes $E_{i'}'^{(2)}$, and the third device only publishes $E_{i''}''^{(3)}$.

## Unlinkability within one publishment (2)

File `unlinkability-within-one-publishment-2.pv`

+ The device follows the protocol and publishes $E_{i}^{(j)}$ using three servers.
+ The device only publishes $E_{i}^{(3)}$ using a server, but it publishes three events each time.

## Unlinkability within one publishment in case of colluding of some servers

File `unlinkability-within-one-publishment-with-colluding.pv` (with exposing the `knowledge` of $S_1$ and $S_3$)

+ Multiple devices follow the protocol and publishes $E_{i}^{(j)}$ using three servers. Servers $S_1$ and $S_3$ disclose all their knowledge to the attacker.
+ Multiple sets of three devices partially publish events while the first device only publishes $E_{i}^{(1)}$, the second device only publishes $E_{i'}'^{(2)}$, and the third device only publishes $E_{i''}''^{(3)}$. Servers $S_1$ and $S_3$ disclose all their knowledge to the attacker.

